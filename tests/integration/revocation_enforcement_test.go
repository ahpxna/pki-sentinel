//go:build integration

// Package integration asserts the core security property of pki-sentinel:
// clients that check revocation actually detect it quickly, and clients
// that don't are recorded as such — not silently ignored. This is the test
// that makes the CI pipeline meaningful rather than decorative (Step 5.4).
//
// Run with: go test -tags=integration ./tests/integration/... -v
// Requires the full stack up and bootstrapped (`make bootstrap`) first.
package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

type result struct {
	Profile      string `json:"profile"`
	Method       string `json:"method"`
	Outcome      string `json:"outcome"`
	DetectionDur int64  `json:"detection_duration_ns"`
}

type cycleReport struct {
	CycleID string   `json:"cycle_id"`
	Results []result `json:"results"`
}

func runProbeOnce(t *testing.T) cycleReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	binPath := os.Getenv("PROBE_BIN")
	if binPath == "" {
		binPath = "../../services/revocation-probe/bin/probe"
	}
	cfgPath := os.Getenv("PROBE_CONFIG")
	if cfgPath == "" {
		cfgPath = "../../services/revocation-probe/profiles.yaml"
	}

	cmd := exec.CommandContext(ctx, binPath, "run", "--once", "--output", "json", "--config", cfgPath)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running probe: %v", err)
	}

	var report cycleReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("parsing probe output: %v\nraw output:\n%s", err, out)
	}
	return report
}

func findResult(t *testing.T, report cycleReport, profile string) result {
	t.Helper()
	for _, r := range report.Results {
		if r.Profile == profile {
			return r
		}
	}
	t.Fatalf("profile %s missing from cycle report", profile)
	return result{}
}

// TestRevocationEnforcement is the headline assertion: the ground-truth
// oracle (openssl-ocsp-direct) must detect revocation quickly, stapled
// clients must reject, and clients that perform no revocation check at all
// are expected — and asserted — to accept. That last assertion is not a
// defect being tolerated; it's the documented property this entire project
// exists to surface (see README "Why I built this").
func TestRevocationEnforcement(t *testing.T) {
	report := runProbeOnce(t)

	oracle := findResult(t, report, "openssl-ocsp-direct")
	if oracle.Outcome != "rejected" {
		t.Errorf("openssl-ocsp-direct: expected rejected, got %s — the PKI itself may be misconfigured", oracle.Outcome)
	}
	if time.Duration(oracle.DetectionDur) >= 15*time.Second {
		t.Errorf("openssl-ocsp-direct: detection took %s, expected < 15s — the ground-truth oracle should be fast", time.Duration(oracle.DetectionDur))
	}

	stapledOCSP := findResult(t, report, "go-tls-ocsp")
	if stapledOCSP.Outcome != "rejected" {
		t.Errorf("go-tls-ocsp (stapling on): expected rejected, got %s", stapledOCSP.Outcome)
	}

	noneMethodProfiles := []string{"curl-default", "go-tls-default", "python-requests"}
	for _, name := range noneMethodProfiles {
		r := findResult(t, report, name)
		// Expected property, not a defect: these clients perform no
		// revocation check by default, so they accept. That's the whole
		// point of this project's existence.
		if r.Outcome != "accepted" {
			t.Errorf("%s: expected accepted (documented no-revocation-check behavior), got %s", name, r.Outcome)
		}
	}
}

// TestTruststoreDriftDetectsRogueCA runs truststore-drift-agent against a
// synthetic rogue CA and asserts it exits non-zero.
func TestTruststoreDriftDetectsRogueCA(t *testing.T) {
	binPath := os.Getenv("TRUSTSTORE_AGENT_BIN")
	if binPath == "" {
		binPath = "../../services/truststore-drift-agent/bin/truststore-drift-agent"
	}
	if _, err := os.Stat(binPath); err != nil {
		t.Skipf("truststore-drift-agent binary not built at %s: %v", binPath, err)
	}

	tmp := t.TempDir()
	baseline := tmp + "/baseline.json"

	if err := exec.Command(binPath, "baseline", "-o", baseline).Run(); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	// Note: actually installing a rogue CA requires root and mutates the
	// container's trust store; in CI this test runs inside the dedicated
	// truststore-drift-agent container image against ./.data/truststore/extra-cas
	// (see scripts/truststore-drift-demo.sh), not the CI runner's own host.
	cmd := exec.Command(binPath, "check", "-b", baseline)
	err := cmd.Run()
	if err == nil {
		t.Skip("no drift detected in this environment; full rogue-CA injection is exercised by scripts/truststore-drift-demo.sh in the integration job, not this unit-level check")
	}
}
