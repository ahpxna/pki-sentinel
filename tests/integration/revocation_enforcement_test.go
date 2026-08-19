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
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type result struct {
	Profile      string `json:"profile"`
	Method       string `json:"method"`
	Outcome      string `json:"outcome"`
	DetectionDur int64  `json:"detection_duration_ns"`
	Error        string `json:"error"`
}

type cycleReport struct {
	CycleID string   `json:"cycle_id"`
	Results []result `json:"results"`
}

func runProbeOnce(t *testing.T) cycleReport {
	t.Helper()
	if reportPath := os.Getenv("PROBE_REPORT"); reportPath != "" {
		out, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("reading PROBE_REPORT %s: %v", reportPath, err)
		}
		var report cycleReport
		if err := json.Unmarshal(out, &report); err != nil {
			t.Fatalf("parsing PROBE_REPORT: %v\nraw output:\n%s", err, out)
		}
		return report
	}

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
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running probe: %v\n%s", err, out)
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
// exists to surface (see README "Rationale").
func TestRevocationEnforcement(t *testing.T) {
	report := runProbeOnce(t)
	if report.CycleID == "" || len(report.Results) == 0 {
		t.Fatal("probe returned an empty cycle report")
	}

	oracle := findResult(t, report, "openssl-ocsp-direct")
	if oracle.Outcome != "rejected" {
		t.Errorf("openssl-ocsp-direct: expected rejected, got %s — the PKI itself may be misconfigured", oracle.Outcome)
	}
	if time.Duration(oracle.DetectionDur) >= 15*time.Second {
		t.Errorf("openssl-ocsp-direct: detection took %s, expected < 15s — the ground-truth oracle should be fast", time.Duration(oracle.DetectionDur))
	}

	for _, r := range report.Results {
		if r.Error != "" || r.Outcome == "error" {
			t.Errorf("%s: harness error: %s", r.Profile, r.Error)
			continue
		}
		if r.Method == "none" {
			// Expected property, not a defect: these clients perform no
			// revocation check by default, so they accept.
			if r.Outcome != "accepted" {
				t.Errorf("%s: expected accepted (documented no-revocation-check behavior), got %s", r.Profile, r.Outcome)
			}
		} else if r.Outcome != "rejected" {
			t.Errorf("%s (%s): expected rejected, got %s", r.Profile, r.Method, r.Outcome)
		}
	}
}

// TestCycleMetrics waits for the continuously running Compose probe to finish
// a cycle and asserts that it has not recorded a harness error.
func TestCycleMetrics(t *testing.T) {
	metricsURL := os.Getenv("PROBE_METRICS_URL")
	if metricsURL == "" {
		metricsURL = "http://localhost:9110/metrics"
	}
	deadline := time.Now().Add(4 * time.Minute)
	for {
		resp, err := http.Get(metricsURL) // #nosec G107 -- explicit integration-test endpoint.
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				text := string(body)
				if strings.Contains(text, `pki_revocation_cycle_total{result="error"} `) &&
					!strings.Contains(text, `pki_revocation_cycle_total{result="error"} 0`) {
					t.Fatalf("probe recorded an error cycle:\n%s", text)
				}
				if strings.Contains(text, `pki_revocation_cycle_total{result="ok"} `) {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a completed probe cycle at %s", metricsURL)
		}
		time.Sleep(2 * time.Second)
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
	privateKey := tmp + "/baseline.key"
	publicKey := tmp + "/baseline.pub"

	extraCADir := filepath.Join(tmp, "extra-cas")
	if err := os.Mkdir(extraCADir, 0o755); err != nil {
		t.Fatal(err)
	}
	baselineCmd := exec.Command(binPath, "baseline", "-o", baseline,
		"--private-key", privateKey, "--public-key", publicKey, "--extra-ca-dir", extraCADir)
	if out, err := baselineCmd.CombinedOutput(); err != nil {
		t.Fatalf("baseline: %v\n%s", err, out)
	}

	rogueCert := filepath.Join(extraCADir, "rogue.crt")
	rogueKey := filepath.Join(tmp, "rogue.key")
	openssl := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
		"-subj", "/CN=Rogue MITM CA", "-out", rogueCert, "-keyout", rogueKey)
	if out, err := openssl.CombinedOutput(); err != nil {
		t.Fatalf("generating synthetic rogue CA: %v\n%s", err, out)
	}

	logPath := filepath.Join(tmp, "drift.json")
	cmd := exec.Command(binPath, "check", "-b", baseline, "--public-key", publicKey,
		"--extra-ca-dir", extraCADir, "--log", logPath)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected drift check exit code 1, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Rogue MITM CA") {
		t.Fatalf("drift output did not identify rogue CA:\n%s", out)
	}
	if data, readErr := os.ReadFile(logPath); readErr != nil || !strings.Contains(string(data), "Rogue MITM CA") {
		t.Fatalf("drift log missing rogue CA event: readErr=%v data=%s", readErr, data)
	}
}
