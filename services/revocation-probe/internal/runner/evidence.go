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
		evidence := &results[i].Evidence
		for _, raw := range evidence.RawArtifacts {
			contents, err := rawArtifactBytes(raw)
			if err != nil {
				return fmt.Errorf("decode %s/%s: %w", results[i].Profile, raw.Name, err)
			}
			digest := sha256.Sum256(contents)
			name := safeArtifactName(raw.Name)
			directory := filepath.Join(r.EvidenceDir, cycleID, results[i].Profile)
			if err := os.MkdirAll(directory, 0o750); err != nil {
				return fmt.Errorf("create evidence directory: %w", err)
			}
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, contents, 0o640); err != nil {
				return fmt.Errorf("write evidence %s: %w", path, err)
			}
			evidence.Artifacts = append(evidence.Artifacts, profiles.Artifact{
				Path: filepath.ToSlash(filepath.Join(cycleID, results[i].Profile, name)), SHA256: hex.EncodeToString(digest[:]), MediaType: raw.MediaType,
			})
		}
		evidence.RawArtifacts = nil
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
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, fmt.Errorf("create cycle evidence directory: %w", err)
	}
	references := make([]profiles.Artifact, 0, len(artifacts))
	for name, artifact := range artifacts {
		name = safeArtifactName(name)
		if err := os.WriteFile(filepath.Join(directory, name), artifact.Contents, 0o640); err != nil {
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
