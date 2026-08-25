package runner

import (
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
	for _, raw := range evidence.RawArtifacts {
		contents, err := rawArtifactBytes(raw)
		if err != nil {
			return fmt.Errorf("decode %s/%s: %w", profile, raw.Name, err)
		}
		digest := sha256.Sum256(contents)
		name := safeArtifactName(raw.Name)
		directory := filepath.Join(r.EvidenceDir, cycleID, profile, phase)
		if err := ensurePrivateDir(directory); err != nil {
			return fmt.Errorf("create evidence directory: %w", err)
		}
		path := filepath.Join(directory, name)
		if err := writeNewPrivateFile(path, contents); err != nil {
			return fmt.Errorf("write evidence %s: %w", path, err)
		}
		evidence.Artifacts = append(evidence.Artifacts, profiles.Artifact{
			Path: filepath.ToSlash(filepath.Join(cycleID, profile, phase, name)), SHA256: hex.EncodeToString(digest[:]), MediaType: raw.MediaType,
		})
	}
	sort.Slice(evidence.Artifacts, func(i, j int) bool { return evidence.Artifacts[i].Path < evidence.Artifacts[j].Path })
	evidence.RawArtifacts = nil
	return nil
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	// MkdirAll does not change the mode of an existing directory.
	return os.Chmod(path, 0o700)
}

func writeNewPrivateFile(path string, contents []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(writeErr error) error {
		_ = f.Close()
		_ = os.Remove(path)
		return writeErr
	}
	if _, err := f.Write(contents); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
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
	directory := filepath.Join(r.EvidenceDir, cycleID)
	if err := ensurePrivateDir(directory); err != nil {
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
		if err := writeNewPrivateFile(filepath.Join(directory, name), artifact.Contents); err != nil {
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
