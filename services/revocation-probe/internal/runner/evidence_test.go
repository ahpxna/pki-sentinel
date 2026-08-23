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
}
