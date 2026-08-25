package runner

import (
	"bytes"
	"testing"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

func TestCycleReportCanonicalJSONIsStableAndCompact(t *testing.T) {
	t.Parallel()
	report := &CycleReport{
		CycleID:        "cycle-1",
		Scenario:       profiles.Scenario("revoked_staple"),
		ScenarioDigest: "sha256:scenario",
		RevokeAckAt:    time.Date(2026, 8, 25, 21, 0, 0, 0, time.UTC),
		Results:        []profiles.Result{},
	}

	first, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical report bytes changed between serializations:\nfirst:  %q\nsecond: %q", first, second)
	}
	if bytes.Contains(first, []byte("\n")) || bytes.HasSuffix(first, []byte("\n")) {
		t.Fatalf("canonical report must be compact and newline-free: %q", first)
	}
}

func TestNilCycleReportCanonicalJSONFails(t *testing.T) {
	t.Parallel()
	var report *CycleReport
	if _, err := report.CanonicalJSON(); err == nil {
		t.Fatal("nil cycle report serialized successfully")
	}
}
