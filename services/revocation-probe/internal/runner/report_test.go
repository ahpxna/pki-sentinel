package runner

import (
	"bytes"
	"testing"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

func TestCycleReportCanonicalJSONIsStableAndCompact(t *testing.T) {
	t.Parallel()
	report := &CycleReport{
		CycleID:         "cycle-1",
		Scenario:        profiles.Scenario("revoked_staple"),
		ScenarioDigest:  "sha256:scenario",
		RunConfigDigest: "sha256:config",
		RevokeAckAt:     time.Date(2026, 8, 25, 21, 0, 0, 0, time.UTC),
		Results:         []profiles.Result{},
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

func TestRunConfigDigestBindsEffectiveExecutionInputs(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Second, MaxWait: 10 * time.Second, MaxAttempts: 5, PreflightMaxAge: 2 * time.Second,
		OCSPFreshness: config.OCSPFreshnessConfig{MaxClockSkew: time.Minute, RequireNextUpdate: true, MaxAgeWithoutNextUpdate: time.Hour},
		Profiles:      []config.ProfileConfig{{Name: "client", Enabled: true, Timeout: 3 * time.Second}},
	}, Profiles: []profiles.Profile{{Name: "client", Role: profiles.RoleClientExecutor, Method: profiles.MethodOCSPStapled}}}
	first := r.runConfigSnapshot()
	if first.ProfileConfigDigest == "" {
		t.Fatal("profile_config_digest is empty")
	}
	firstDigest, err := digestRunConfig(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := digestRunConfig(r.runConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("run config digest is unstable: %s != %s", firstDigest, secondDigest)
	}
	r.Config.Profiles[0].Timeout = 4 * time.Second
	changedDigest, err := digestRunConfig(r.runConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == firstDigest {
		t.Fatal("run config digest did not change when an enabled profile timeout changed")
	}
	r.Config.Profiles[0].Timeout = 3 * time.Second
	r.ExecutorURLs = map[string]string{"client": "http://executor-a:8120"}
	executorDigest, err := digestRunConfig(r.runConfigSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if executorDigest == firstDigest {
		t.Fatal("run config digest did not change when executor mapping changed")
	}
}
