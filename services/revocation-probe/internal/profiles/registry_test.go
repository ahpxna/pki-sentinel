package profiles

import "testing"

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
		for _, scenario := range []Scenario{ScenarioRevokedStaple, ScenarioMissingStaple, ScenarioCachedGoodStaple} {
			if _, ok := p.Expected(scenario); !ok {
				t.Errorf("profile %s: missing expectation for scenario %s", p.Name, scenario)
			}
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
