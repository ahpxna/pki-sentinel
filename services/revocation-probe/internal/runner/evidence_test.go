package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

func TestPersistEvidenceStoresContentAddressedArtifact(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{EvidenceDir: dir}
	results := []profiles.Result{{
		Profile:  "curl-default",
		Evidence: profiles.CommandEvidence{RawArtifacts: []profiles.RawArtifact{{Name: "stderr.txt", MediaType: "text/plain", Data: "certificate revoked"}}},
	}}
	if err := r.persistEvidence("run-1", results); err != nil {
		t.Fatal(err)
	}
	if len(results[0].Evidence.Artifacts) != 1 || len(results[0].Evidence.RawArtifacts) != 0 {
		t.Fatalf("unexpected evidence: %#v", results[0].Evidence)
	}
	path := filepath.Join(dir, "run-1", "curl-default", "stderr.txt")
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "certificate revoked" {
		t.Fatalf("artifact = %q, err=%v", contents, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("artifact mode = %o, want 600", got)
	}
}

func TestPersistCycleArtifactsStoresCertificateMaterial(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{EvidenceDir: dir}
	references, err := r.persistCycleArtifacts("run-2", map[string]cycleArtifact{
		"leaf.pem": {MediaType: "application/x-pem-file", Contents: []byte("leaf")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 1 || references[0].Path != "run-2/leaf.pem" {
		t.Fatalf("unexpected references: %#v", references)
	}
	want := sha256.Sum256([]byte("leaf"))
	if references[0].SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s", references[0].SHA256)
	}
	info, err := os.Stat(filepath.Join(dir, "run-2", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("cycle artifact mode = %o, want 600", got)
	}
}

func TestPersistEvidenceTightensExistingPermissions(t *testing.T) {
	dir := t.TempDir()
	directory := filepath.Join(dir, "run-existing", "curl-default")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "stderr.txt")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}

	r := &Runner{EvidenceDir: dir}
	results := []profiles.Result{{
		Profile: "curl-default",
		Evidence: profiles.CommandEvidence{RawArtifacts: []profiles.RawArtifact{{
			Name: "stderr.txt", MediaType: "text/plain", Data: "new",
		}}},
	}}
	if err := r.persistEvidence("run-existing", results); err != nil {
		t.Fatal(err)
	}

	dirInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("existing evidence directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing artifact mode = %o, want 600", got)
	}
}
