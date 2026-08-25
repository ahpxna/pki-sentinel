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
	"encoding/hex"
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
	Profile          string   `json:"profile"`
	Role             string   `json:"role"`
	Method           string   `json:"method"`
	Decision         string   `json:"decision"`
	Reason           string   `json:"reason"`
	ExpectedDecision string   `json:"expected_decision"`
	ExpectedReasons  []string `json:"expected_reasons"`
	ExpectationMet   bool     `json:"expectation_met"`
	DecisionLatency  int64    `json:"decision_latency_ns"`
	Error            string   `json:"error"`
}

type cycleReport struct {
	CycleID        string   `json:"cycle_id"`
	Scenario       string   `json:"scenario"`
	ScenarioDigest string   `json:"scenario_digest"`
	Results        []result `json:"results"`
}

type attestationEnvelope struct {
	Statement struct {
		ScenarioDigest string `json:"scenario_digest"`
	} `json:"statement"`
	Payload json.RawMessage `json:"payload"`
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
// status oracle must confirm REVOKED quickly, then every client executor must
// satisfy its explicit scenario contract. Decision and reason are asserted
// separately so a network or TLS failure cannot masquerade as enforcement.
func TestRevocationEnforcement(t *testing.T) {
	report := runProbeOnce(t)
	if report.CycleID == "" || len(report.Results) == 0 {
		t.Fatal("probe returned an empty cycle report")
	}
	if report.Scenario != "revoked_staple" {
		t.Fatalf("probe scenario=%q, want revoked_staple", report.Scenario)
	}
	if !validScenarioDigest(report.ScenarioDigest) {
		t.Fatalf("probe report has invalid scenario_digest %q", report.ScenarioDigest)
	}

	oracle := findResult(t, report, "openssl-ocsp-direct")
	if oracle.Role != "status_oracle" || oracle.Decision != "REJECT" || oracle.Reason != "REVOKED" {
		t.Errorf("openssl-ocsp-direct: expected status_oracle REJECT/REVOKED, got role=%s decision=%s reason=%s", oracle.Role, oracle.Decision, oracle.Reason)
	}
	if time.Duration(oracle.DecisionLatency) >= 15*time.Second {
		t.Errorf("openssl-ocsp-direct: decision took %s, expected < 15s", time.Duration(oracle.DecisionLatency))
	}

	for _, r := range report.Results {
		if r.Error != "" || r.Decision == "HARNESS_ERROR" {
			t.Errorf("%s: harness error: %s", r.Profile, r.Error)
			continue
		}
		if !r.ExpectationMet || r.Decision != r.ExpectedDecision {
			t.Errorf("%s (%s): decision=%s reason=%s expected=%s", r.Profile, r.Method, r.Decision, r.Reason, r.ExpectedDecision)
		}
		reasonAllowed := false
		for _, expectedReason := range r.ExpectedReasons {
			if r.Reason == expectedReason {
				reasonAllowed = true
				break
			}
		}
		if len(r.ExpectedReasons) > 0 && !reasonAllowed {
			t.Errorf("%s: reason=%s expected one of %v", r.Profile, r.Reason, r.ExpectedReasons)
		}
	}
}

// TestAttestationBindsScenarioDigest verifies the integration cycle's actual
// envelope, not a synthetic payload. CI provisions these paths alongside the
// cycle report; local report-only runs skip this explicit signature check.
func TestAttestationBindsScenarioDigest(t *testing.T) {
	attestationPath := os.Getenv("PROBE_ATTESTATION")
	publicKeyPath := os.Getenv("PROBE_ATTESTATION_PUBLIC_KEY")
	if attestationPath == "" || publicKeyPath == "" {
		t.Skip("PROBE_ATTESTATION and PROBE_ATTESTATION_PUBLIC_KEY are not configured")
	}
	report := runProbeOnce(t)
	contents, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatalf("reading attestation %s: %v", attestationPath, err)
	}
	var envelope attestationEnvelope
	if err := json.Unmarshal(contents, &envelope); err != nil {
		t.Fatalf("parsing attestation: %v", err)
	}
	if envelope.Statement.ScenarioDigest != report.ScenarioDigest {
		t.Fatalf("attestation digest=%q, report digest=%q", envelope.Statement.ScenarioDigest, report.ScenarioDigest)
	}
	var payload cycleReport
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("parsing attestation payload: %v", err)
	}
	if payload.Scenario != report.Scenario || payload.ScenarioDigest != report.ScenarioDigest {
		t.Fatalf("attestation payload does not match report scenario identity: %#v", payload)
	}
	binPath := os.Getenv("PROBE_BIN")
	if binPath == "" {
		binPath = "../../services/revocation-probe/bin/probe"
	}
	cmd := exec.Command(binPath, "attest", "verify", "--public-key", publicKeyPath, "--input", attestationPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verifying attestation: %v\n%s", err, output)
	}
}

func validScenarioDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
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
