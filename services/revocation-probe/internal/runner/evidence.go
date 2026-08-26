package runner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

// persistEvidence turns executor transport records into durable evidence. Raw
// data is removed from the report only after its content-addressed artifact is
// written, allowing a verifier to recompute each hash independently.
func (r *Runner) persistEvidence(cycleID string, results []profiles.Result) error {
	if r.EvidenceDir == "" {
		return fmt.Errorf("evidence directory is required")
	}
	for i := range results {
		// i is produced by ranging over this exact slice, so the access is
		// bounds-safe. Keeping the indexed access on one reviewed line also
		// avoids repeatedly indexing the slice while evidence is mutated.
		result := &results[i] //nolint:gosec // G602: i is the range index for results.
		if err := r.persistResultEvidence(cycleID, result); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) persistResultEvidence(cycleID string, result *profiles.Result) error {
	return r.persistCommandEvidence(cycleID, result.Profile, "post_revocation", &result.Evidence)
}

func (r *Runner) persistPreflightEvidence(cycleID string, results []profiles.PreflightResult) error {
	if r.EvidenceDir == "" {
		return fmt.Errorf("evidence directory is required")
	}
	for i := range results {
		result := &results[i] //nolint:gosec // G602: i is the range index for results.
		if err := r.persistCommandEvidence(cycleID, result.Profile, "pre_revocation", &result.Evidence); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) persistCommandEvidence(cycleID, profile, phase string, evidence *profiles.CommandEvidence) error {
	names := make(map[string]struct{}, len(evidence.RawArtifacts))
	for _, raw := range evidence.RawArtifacts {
		name := safeArtifactName(raw.Name)
		if _, duplicate := names[name]; duplicate {
			return fmt.Errorf("profile %s %s evidence has colliding artifact name %q", profile, phase, name)
		}
		names[name] = struct{}{}
	}
	root, err := openEvidenceRoot(r.EvidenceDir)
	if err != nil {
		return err
	}
	defer root.Close()
	directory := filepath.Join(cycleID, profile, phase)
	if err := ensurePrivateRootDir(root, directory); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	for _, raw := range evidence.RawArtifacts {
		contents, err := rawArtifactBytes(raw)
		if err != nil {
			return fmt.Errorf("decode %s/%s: %w", profile, raw.Name, err)
		}
		digest := sha256.Sum256(contents)
		name := safeArtifactName(raw.Name)
		relPath := filepath.Join(directory, name)
		if err := writeNewPrivateRootFile(root, relPath, contents); err != nil {
			return fmt.Errorf("write evidence %s: %w", filepath.Join(r.EvidenceDir, relPath), err)
		}
		evidence.Artifacts = append(evidence.Artifacts, profiles.Artifact{
			Path: filepath.ToSlash(relPath), SHA256: hex.EncodeToString(digest[:]), MediaType: raw.MediaType,
		})
	}
	sort.Slice(evidence.Artifacts, func(i, j int) bool { return evidence.Artifacts[i].Path < evidence.Artifacts[j].Path })
	evidence.RawArtifacts = nil
	return nil
}

func openEvidenceRoot(path string) (*os.Root, error) {
	if path == "" {
		return nil, fmt.Errorf("evidence directory is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence root: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat evidence root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("evidence root must be a real directory, got %s", info.Mode())
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return nil, fmt.Errorf("restrict evidence root permissions: %w", err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	return root, nil
}

func ensurePrivateRootDir(root *os.Root, path string) error {
	cleaned, err := cleanEvidenceRelativePath(path)
	if err != nil {
		return err
	}
	if cleaned == "." {
		return syncRootDir(root, ".")
	}
	current := "."
	for _, component := range strings.Split(cleaned, string(filepath.Separator)) {
		parent := current
		if current == "." {
			current = component
		} else {
			current = filepath.Join(current, component)
		}
		info, statErr := root.Lstat(current)
		created := false
		switch {
		case statErr == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("evidence directory component %q is a symbolic link", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("evidence directory component %q is not a directory", current)
			}
		case os.IsNotExist(statErr):
			if err := root.Mkdir(current, 0o700); err != nil {
				return err
			}
			created = true
			info, statErr = root.Lstat(current)
			if statErr != nil {
				return statErr
			}
		default:
			return statErr
		}
		if info.Mode().Perm() != 0o700 {
			if err := root.Chmod(current, 0o700); err != nil {
				return fmt.Errorf("restrict evidence directory %q permissions: %w", current, err)
			}
		}
		if created {
			if err := syncRootDir(root, parent); err != nil {
				return fmt.Errorf("sync parent evidence directory %q: %w", parent, err)
			}
		}
	}
	return syncRootDir(root, cleaned)
}

func cleanEvidenceRelativePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("evidence path %q escapes evidence root", path)
	}
	return cleaned, nil
}

func syncRootDir(root *os.Root, path string) error {
	dir, err := root.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeNewPrivateRootFile(root *os.Root, path string, contents []byte) error {
	cleaned, err := cleanEvidenceRelativePath(path)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(cleaned, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(writeErr error) error {
		_ = f.Close()
		_ = root.Remove(cleaned)
		return writeErr
	}
	if _, err := f.Write(contents); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(cleaned)
		return err
	}
	parent := filepath.Dir(cleaned)
	if err := syncRootDir(root, parent); err != nil {
		_ = root.Remove(cleaned)
		_ = syncRootDir(root, parent)
		return fmt.Errorf("sync evidence directory: %w", err)
	}
	return nil
}

// archiveCycleJSON retains signed-report inputs beside the certificate and
// raw probe artifacts for the same immutable cycle directory.
func (r *Runner) ArchiveCycleReport(cycleID string, contents []byte) error {
	return r.archiveCycleFile(cycleID, "report.json", contents)
}

// ArchiveCycleAttestation retains the signed envelope for its exact cycle.
func (r *Runner) ArchiveCycleAttestation(cycleID string, contents []byte) error {
	return r.archiveCycleFile(cycleID, "attestation.json", contents)
}

func (r *Runner) archiveCycleFile(cycleID, name string, contents []byte) error {
	if r.EvidenceDir == "" {
		return fmt.Errorf("evidence directory is required")
	}
	root, err := openEvidenceRoot(r.EvidenceDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := ensurePrivateRootDir(root, cycleID); err != nil {
		return fmt.Errorf("create cycle evidence directory: %w", err)
	}
	return writeAtomicPrivateRootFile(root, filepath.Join(cycleID, safeArtifactName(name)), contents, false)
}

// UpdateLatestCycleReport and UpdateLatestCycleAttestation maintain atomic
// convenience copies. Historical verification must use the per-cycle files.
func (r *Runner) UpdateLatestCycleReport(contents []byte) error {
	return r.updateLatestCycleFile("last-cycle.json", contents)
}

func (r *Runner) UpdateLatestCycleAttestation(contents []byte) error {
	return r.updateLatestCycleFile("last-cycle.attestation.json", contents)
}

func (r *Runner) updateLatestCycleFile(name string, contents []byte) error {
	if r.EvidenceDir == "" {
		return fmt.Errorf("evidence directory is required")
	}
	root, err := openEvidenceRoot(r.EvidenceDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return writeAtomicPrivateRootFile(root, safeArtifactName(name), contents, true)
}

// writeAtomicPrivateFile durably publishes an evidence file after its content
// is synced. Immutable cycle files reject replacement; latest-cycle copies are
// explicitly replaceable convenience pointers.
func writeAtomicPrivateRootFile(root *os.Root, path string, contents []byte, replace bool) error {
	cleaned, err := cleanEvidenceRelativePath(path)
	if err != nil {
		return err
	}
	if !replace {
		// O_EXCL makes the no-replacement property atomic. A prior Lstat
		// followed by Rename is a TOCTOU: on Unix Rename replaces a target
		// created by a concurrent writer between those operations.
		return writeNewPrivateRootFile(root, cleaned, contents)
	}
	parent := filepath.Dir(cleaned)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("generate evidence temporary name: %w", err)
	}
	temporaryName := filepath.Join(parent, fmt.Sprintf(".evidence-%x", suffix))
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Remove(temporaryName)
	}()
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, cleaned); err != nil {
		return err
	}
	return syncRootDir(root, parent)
}

type cycleArtifact struct {
	MediaType string
	Contents  []byte
}

// persistCycleArtifacts retains the certificate material that defines the
// exact target evaluated by a cycle. It complements profile-specific command,
// OCSP, and CRL artifacts.
func (r *Runner) persistCycleArtifacts(cycleID string, artifacts map[string]cycleArtifact) ([]profiles.Artifact, error) {
	if r.EvidenceDir == "" {
		return nil, fmt.Errorf("evidence directory is required")
	}
	root, err := openEvidenceRoot(r.EvidenceDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := ensurePrivateRootDir(root, cycleID); err != nil {
		return nil, fmt.Errorf("create cycle evidence directory: %w", err)
	}
	references := make([]profiles.Artifact, 0, len(artifacts))
	keys := make([]string, 0, len(artifacts))
	for name := range artifacts {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	seen := make(map[string]struct{}, len(keys))
	for _, rawName := range keys {
		artifact := artifacts[rawName]
		name := safeArtifactName(rawName)
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("cycle evidence has colliding artifact name %q", name)
		}
		seen[name] = struct{}{}
		if err := writeNewPrivateRootFile(root, filepath.Join(cycleID, name), artifact.Contents); err != nil {
			return nil, fmt.Errorf("write cycle artifact %s: %w", name, err)
		}
		digest := sha256.Sum256(artifact.Contents)
		references = append(references, profiles.Artifact{
			Path: filepath.ToSlash(filepath.Join(cycleID, name)), SHA256: hex.EncodeToString(digest[:]), MediaType: artifact.MediaType,
		})
	}
	sort.Slice(references, func(i, j int) bool { return references[i].Path < references[j].Path })
	return references, nil
}

func rawArtifactBytes(raw profiles.RawArtifact) ([]byte, error) {
	switch raw.Encoding {
	case "", "utf-8":
		return []byte(raw.Data), nil
	case "base64":
		contents, err := base64.StdEncoding.DecodeString(raw.Data)
		if err != nil {
			return nil, fmt.Errorf("base64: %w", err)
		}
		return contents, nil
	default:
		return nil, fmt.Errorf("unsupported encoding %q", raw.Encoding)
	}
}

func safeArtifactName(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "..", "_")
	if name == "." || name == "" {
		return "artifact"
	}
	return name
}
