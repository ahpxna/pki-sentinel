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
	"bytes"
	"context"
	"crypto/sha256"
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

type commandEvidence struct {
	PresentedLeafSHA256 string `json:"presented_leaf_sha256"`
}

type result struct {
	Profile             string               `json:"profile"`
	Role                string               `json:"role"`
	Method              string               `json:"method"`
	Decision            string               `json:"decision"`
	Reason              string               `json:"reason"`
	ExpectedDecision    string               `json:"expected_decision"`
	ExpectedReasons     []string             `json:"expected_reasons"`
	ExpectationMet      bool                 `json:"expectation_met"`
	ObservedAt          time.Time            `json:"observed_at"`
	AgeAtRevoke         int64                `json:"age_at_revoke_ns"`
	ClientAttemptAt     time.Time            `json:"client_attempt_at"`
	RequiredEvidence    []string             `json:"required_evidence"`
	EvidenceSatisfiedAt map[string]time.Time `json:"evidence_satisfied_at"`
	DecisionLatency     int64                `json:"decision_latency_ns"`
	Evidence            commandEvidence      `json:"evidence"`
	Error               string               `json:"error"`
}

type cycleReport struct {
	CycleID          string   `json:"cycle_id"`
	Scenario         string   `json:"scenario"`
	ScenarioDigest   string   `json:"scenario_digest"`
	RunConfigDigest  string   `json:"run_config_digest"`
	IssuedLeafSHA256 string   `json:"issued_leaf_sha256"`
	Valid            bool     `json:"valid"`
	Phase            string   `json:"phase"`
	Preflight        []result `json:"preflight"`
	Results          []result `json:"results"`
}

type attestationEnvelope struct {
	Statement struct {
		ScenarioDigest  string `json:"scenario_digest"`
		RunConfigDigest string `json:"run_config_digest"`
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
	if !validSHA256Digest(report.ScenarioDigest) {
		t.Fatalf("probe report has invalid scenario_digest %q", report.ScenarioDigest)
	}
	if !validSHA256Digest(report.RunConfigDigest) {
		t.Fatalf("probe report has invalid run_config_digest %q", report.RunConfigDigest)
	}
	if len(report.IssuedLeafSHA256) != sha256.Size*2 {
		t.Fatalf("probe report has invalid issued_leaf_sha256 %q", report.IssuedLeafSHA256)
	}
	if !report.Valid || report.Phase != "complete" {
		t.Fatalf("probe cycle validity=%v phase=%q, want valid complete cycle", report.Valid, report.Phase)
	}
	if len(report.Preflight) != len(report.Results) {
		t.Fatalf("preflight observations=%d, post-revocation results=%d", len(report.Preflight), len(report.Results))
	}
	for _, before := range report.Preflight {
		if before.Error != "" || !before.ExpectationMet {
			t.Errorf("preflight %s did not satisfy BEFORE contract: decision=%s reason=%s error=%s", before.Profile, before.Decision, before.Reason, before.Error)
		}
		if before.ObservedAt.IsZero() || before.AgeAtRevoke < 0 || time.Duration(before.AgeAtRevoke) > 2*time.Second {
			t.Errorf("preflight %s has invalid causal age: observed_at=%s age=%s", before.Profile, before.ObservedAt, time.Duration(before.AgeAtRevoke))
		}
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
		if r.Role == "status_oracle" && r.Evidence.PresentedLeafSHA256 != report.IssuedLeafSHA256 {
			t.Errorf("%s: presented leaf %q does not match issued leaf %q", r.Profile, r.Evidence.PresentedLeafSHA256, report.IssuedLeafSHA256)
		}
		for _, dependency := range r.RequiredEvidence {
			satisfiedAt, ok := r.EvidenceSatisfiedAt[dependency]
			if !ok || satisfiedAt.IsZero() {
				t.Errorf("%s: required evidence %s has no satisfaction timestamp", r.Profile, dependency)
				continue
			}
			if r.Role == "client_executor" {
				if r.ClientAttemptAt.IsZero() {
					t.Errorf("%s: client executor has no client_attempt_at", r.Profile)
				} else if satisfiedAt.After(r.ClientAttemptAt) {
					t.Errorf("%s: evidence %s satisfied at %s after first client attempt %s", r.Profile, dependency, satisfiedAt, r.ClientAttemptAt)
				}
			}
		}
	}

	if scenarioArtifact := os.Getenv("PROBE_SCENARIO_ARTIFACT"); scenarioArtifact != "" {
		contents, err := os.ReadFile(scenarioArtifact)
		if err != nil {
			t.Fatalf("reading canonical scenario artifact: %v", err)
		}
		digest := sha256.Sum256(contents)
		if got := "sha256:" + hex.EncodeToString(digest[:]); got != report.ScenarioDigest {
			t.Fatalf("scenario artifact digest=%s, report scenario_digest=%s", got, report.ScenarioDigest)
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
	if reportPath := os.Getenv("PROBE_REPORT"); reportPath != "" {
		reportBytes, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("reading PROBE_REPORT %s for attestation comparison: %v", reportPath, err)
		}
		if !bytes.Equal(reportBytes, envelope.Payload) {
			t.Fatalf("stdout report and signed payload differ byte-for-byte\nreport:  %q\npayload: %q", reportBytes, envelope.Payload)
		}
	}
	if envelope.Statement.ScenarioDigest != report.ScenarioDigest {
		t.Fatalf("attestation scenario digest=%q, report digest=%q", envelope.Statement.ScenarioDigest, report.ScenarioDigest)
	}
	if envelope.Statement.RunConfigDigest != report.RunConfigDigest {
		t.Fatalf("attestation run-config digest=%q, report digest=%q", envelope.Statement.RunConfigDigest, report.RunConfigDigest)
	}
	var payload cycleReport
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatalf("parsing attestation payload: %v", err)
	}
	if payload.Scenario != report.Scenario || payload.ScenarioDigest != report.ScenarioDigest || payload.RunConfigDigest != report.RunConfigDigest {
		t.Fatalf("attestation payload does not match report experiment identity: %#v", payload)
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

func validSHA256Digest(value string) bool {
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
