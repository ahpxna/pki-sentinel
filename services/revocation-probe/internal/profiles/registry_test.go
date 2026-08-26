package profiles

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestRegistryHasSevenBaselineProfiles(t *testing.T) {
	reg := Registry()
	if len(reg) != 7 {
		t.Fatalf("expected 7 baseline profiles, got %d", len(reg))
	}

	wantMethods := map[string]CheckMethod{
		"openssl-ocsp-direct": MethodOCSPDirect,
		"curl-cert-status":    MethodOCSPStapled,
		"curl-default":        MethodNone,
		"go-tls-default":      MethodNone,
		"go-hardfail-ocsp":    MethodOCSPStapled,
		"python-requests":     MethodNone,
		"crl-check":           MethodCRL,
	}

	seen := map[string]bool{}
	for _, p := range reg {
		if p.Probe == nil {
			t.Errorf("profile %s has a nil Probe func", p.Name)
		}
		wantMethod, ok := wantMethods[p.Name]
		if !ok {
			t.Errorf("unexpected profile name %s", p.Name)
			continue
		}
		if p.Method != wantMethod {
			t.Errorf("profile %s: expected method %s, got %s", p.Name, wantMethod, p.Method)
		}
		if p.Role != RoleStatusOracle && p.Role != RoleClientExecutor {
			t.Errorf("profile %s: invalid role %q", p.Name, p.Role)
		}
		seen[p.Name] = true
	}
	for name := range wantMethods {
		if !seen[name] {
			t.Errorf("missing expected profile %s", name)
		}
	}
}

func TestCurlCertStatusMissingStapleIsRejected(t *testing.T) {
	decision, reason := classifyCurlCertStatus("curl: (91) No OCSP response received", 91, true)
	if decision != DecisionReject || reason != ReasonMissingStatus {
		t.Fatalf("got decision=%s reason=%s", decision, reason)
	}
}

func TestCurlCertStatusRevokedIsRejected(t *testing.T) {
	decision, reason := classifyCurlCertStatus("certificate status: revoked", 91, true)
	if decision != DecisionReject || reason != ReasonRevoked {
		t.Fatalf("got decision=%s reason=%s", decision, reason)
	}
}

func TestCurlCertStatusTimeoutIsInconclusive(t *testing.T) {
	decision, reason := classifyCurlCertStatus("operation timed out", 28, true)
	if decision != DecisionInconclusive || reason != ReasonNetworkFailure {
		t.Fatalf("got decision=%s reason=%s", decision, reason)
	}
}

func TestExpectationMatchesDecisionAndReason(t *testing.T) {
	expectation := Expectation{
		Before: DecisionReject, BeforeReasons: []Reason{ReasonMissingStatus},
		After: DecisionReject, AfterReasons: []Reason{ReasonRevoked},
	}
	if expectation.MatchesBefore(Observation{Decision: DecisionReject, Reason: ReasonInvalidStatus}) {
		t.Fatal("before contract accepted the wrong rejection reason")
	}
	if !expectation.MatchesBefore(Observation{Decision: DecisionReject, Reason: ReasonMissingStatus}) {
		t.Fatal("before contract rejected the expected reason")
	}
	if expectation.MatchesAfter(Observation{Decision: DecisionReject, Reason: ReasonMissingStatus}) {
		t.Fatal("after contract accepted the wrong rejection reason")
	}
}

func TestCheckOCSPFreshness(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	policy := OCSPFreshnessPolicy{MaxClockSkew: 5 * time.Minute, RequireNextUpdate: true, MaxAgeWithoutNextUpdate: time.Hour}
	if got := checkOCSPFreshness(&ocsp.Response{ThisUpdate: now.Add(-time.Minute), ProducedAt: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute)}, now, policy); got != "" {
		t.Fatalf("fresh response classified %s", got)
	}
	if got := checkOCSPFreshness(&ocsp.Response{ThisUpdate: now.Add(6 * time.Minute), NextUpdate: now.Add(time.Hour)}, now, policy); got != ReasonFutureStatus {
		t.Fatalf("future response classified %s", got)
	}
	if got := checkOCSPFreshness(&ocsp.Response{ThisUpdate: now.Add(-time.Minute)}, now, policy); got != ReasonMissingFreshness {
		t.Fatalf("unbounded response classified %s", got)
	}
	if got := checkOCSPFreshness(&ocsp.Response{ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(-time.Minute)}, now, policy); got != ReasonStaleStatus {
		t.Fatalf("expired response classified %s", got)
	}
}

func TestCheckRevocationTimeRejectsFutureAndImpossibleValues(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	notBefore := now.Add(-time.Hour)
	policy := OCSPFreshnessPolicy{MaxClockSkew: 5 * time.Minute}
	if got := checkRevocationTime(now.Add(-time.Minute), notBefore, now, policy); got != "" {
		t.Fatalf("valid revocation time classified %s", got)
	}
	if got := checkRevocationTime(now.Add(6*time.Minute), notBefore, now, policy); got != ReasonFutureStatus {
		t.Fatalf("future revocation time classified %s", got)
	}
	if got := checkRevocationTime(time.Time{}, notBefore, now, policy); got != ReasonInvalidStatus {
		t.Fatalf("missing revocation time classified %s", got)
	}
	if got := checkRevocationTime(notBefore.Add(-6*time.Minute), notBefore, now, policy); got != ReasonInvalidStatus {
		t.Fatalf("pre-certificate revocation time classified %s", got)
	}
}

func TestVerifyPresentedLeafBindsExactIssuedCertificate(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("issued-leaf-der")}
	sum := sha256.Sum256(leaf.Raw)
	want := hex.EncodeToString(sum[:])
	got, err := verifyPresentedLeaf(Target{IssuedLeafSHA256: want}, leaf)
	if err != nil || got != want {
		t.Fatalf("verifyPresentedLeaf got=%q err=%v, want %q", got, err, want)
	}
	if _, err := verifyPresentedLeaf(Target{IssuedLeafSHA256: strings.Repeat("0", 64)}, leaf); err == nil {
		t.Fatal("verifyPresentedLeaf accepted a different presented certificate")
	}
}

func TestLooksLikeNetworkFailureDoesNotTreatAnyExitErrorAsNetwork(t *testing.T) {
	if !looksLikeNetworkFailure("connect: Connection refused") {
		t.Fatal("connection refusal was not classified as network failure")
	}
	if looksLikeNetworkFailure("Response Verify Failure") {
		t.Fatal("cryptographic verification failure was misclassified as network failure")
	}
}
