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
	path := filepath.Join(dir, "run-1", "curl-default", "post_revocation", "stderr.txt")
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

func TestPersistEvidenceRejectsOverwrite(t *testing.T) {
	dir := t.TempDir()
	directory := filepath.Join(dir, "run-existing", "curl-default", "post_revocation")
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
	if err := r.persistEvidence("run-existing", results); err == nil {
		t.Fatal("persistEvidence overwrote an existing evidence artifact")
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
	if got := fileInfo.Mode().Perm(); got != 0o640 {
		t.Fatalf("existing artifact mode changed after rejected overwrite: %o", got)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "old" {
		t.Fatalf("existing artifact was overwritten: %q", contents)
	}
}

func TestPersistPreflightEvidenceUsesSeparatePhasePath(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{EvidenceDir: dir}
	results := []profiles.PreflightResult{{
		Profile:  "curl-default",
		Evidence: profiles.CommandEvidence{RawArtifacts: []profiles.RawArtifact{{Name: "stderr.txt", MediaType: "text/plain", Data: "before"}}},
	}}
	if err := r.persistPreflightEvidence("run-preflight", results); err != nil {
		t.Fatal(err)
	}
	if len(results[0].Evidence.Artifacts) != 1 {
		t.Fatalf("unexpected preflight evidence: %#v", results[0].Evidence)
	}
	if got := results[0].Evidence.Artifacts[0].Path; got != "run-preflight/curl-default/pre_revocation/stderr.txt" {
		t.Fatalf("preflight artifact path=%q", got)
	}
}

func TestPersistEvidenceRejectsSanitizedNameCollision(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{EvidenceDir: dir}
	results := []profiles.Result{{
		Profile: "curl-default",
		Evidence: profiles.CommandEvidence{RawArtifacts: []profiles.RawArtifact{
			{Name: "first/stderr.txt", Data: "one"},
			{Name: "second/stderr.txt", Data: "two"},
		}},
	}}
	if err := r.persistEvidence("run-collision", results); err == nil {
		t.Fatal("persistEvidence accepted artifact names that collide after sanitization")
	}
}

func TestPersistCycleArtifactsIsDeterministicAndNonOverwriting(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{EvidenceDir: dir}
	artifacts := map[string]cycleArtifact{
		"z.pem": {MediaType: "application/x-pem-file", Contents: []byte("z")},
		"a.pem": {MediaType: "application/x-pem-file", Contents: []byte("a")},
	}
	references, err := r.persistCycleArtifacts("run-order", artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if references[0].Path != "run-order/a.pem" || references[1].Path != "run-order/z.pem" {
		t.Fatalf("cycle artifact order is not deterministic: %#v", references)
	}
	if _, err := r.persistCycleArtifacts("run-order", map[string]cycleArtifact{"a.pem": artifacts["a.pem"]}); err == nil {
		t.Fatal("persistCycleArtifacts overwrote an existing artifact")
	}
}

func TestArchiveCycleReportIsImmutableAndLatestCopyIsReplaceable(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{EvidenceDir: dir}
	if err := r.ArchiveCycleReport("cycle-1", []byte(`{"cycle_id":"cycle-1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := r.ArchiveCycleReport("cycle-1", []byte(`{"replacement":true}`)); err == nil {
		t.Fatal("cycle report archive overwrote immutable evidence")
	}
	if err := r.UpdateLatestCycleReport([]byte(`{"cycle_id":"cycle-1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateLatestCycleReport([]byte(`{"cycle_id":"cycle-2"}`)); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(dir, "last-cycle.json"))
	if err != nil || string(contents) != `{"cycle_id":"cycle-2"}` {
		t.Fatalf("latest cycle report=%q err=%v", contents, err)
	}
}
