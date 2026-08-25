package runner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
	evidence := &result.Evidence
	for _, raw := range evidence.RawArtifacts {
		contents, err := rawArtifactBytes(raw)
		if err != nil {
			return fmt.Errorf("decode %s/%s: %w", result.Profile, raw.Name, err)
		}
		digest := sha256.Sum256(contents)
		name := safeArtifactName(raw.Name)
		directory := filepath.Join(r.EvidenceDir, cycleID, result.Profile)
		if err := ensurePrivateDir(directory); err != nil {
			return fmt.Errorf("create evidence directory: %w", err)
		}
		path := filepath.Join(directory, name)
		if err := writePrivateFile(path, contents); err != nil {
			return fmt.Errorf("write evidence %s: %w", path, err)
		}
		evidence.Artifacts = append(evidence.Artifacts, profiles.Artifact{
			Path: filepath.ToSlash(filepath.Join(cycleID, result.Profile, name)), SHA256: hex.EncodeToString(digest[:]), MediaType: raw.MediaType,
		})
	}
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

func writePrivateFile(path string, contents []byte) error {
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return err
	}
	// WriteFile's mode is only used when the file is created; repair an
	// existing artifact that may have been created by an older release.
	return os.Chmod(path, 0o600)
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
	for name, artifact := range artifacts {
		name = safeArtifactName(name)
		if err := writePrivateFile(filepath.Join(directory, name), artifact.Contents); err != nil {
			return nil, fmt.Errorf("write cycle artifact %s: %w", name, err)
		}
		digest := sha256.Sum256(artifact.Contents)
		references = append(references, profiles.Artifact{
			Path: filepath.ToSlash(filepath.Join(cycleID, name)), SHA256: hex.EncodeToString(digest[:]), MediaType: artifact.MediaType,
		})
	}
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
