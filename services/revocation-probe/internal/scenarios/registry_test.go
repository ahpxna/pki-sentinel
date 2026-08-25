package scenarios

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

func productionScenarioDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "scenarios")
}

func TestProductionManifestsValidateAndHaveStableDigests(t *testing.T) {
	t.Parallel()
	implementations := profiles.Registry()
	first, err := LoadDir(productionScenarioDir(t), implementations)
	if err != nil {
		t.Fatalf("load production manifests: %v", err)
	}
	if err := first.ValidateEnabledProfiles(profileNames(implementations)); err != nil {
		t.Fatalf("validate enabled profiles: %v", err)
	}
	second, err := LoadDir(productionScenarioDir(t), implementations)
	if err != nil {
		t.Fatalf("reload production manifests: %v", err)
	}
	for _, scenario := range []profiles.Scenario{profiles.ScenarioRevokedStaple, profiles.ScenarioMissingStaple, profiles.ScenarioCachedGoodStaple} {
		firstDigest, ok := first.Digest(scenario)
		if !ok || !strings.HasPrefix(firstDigest, "sha256:") || len(firstDigest) != len("sha256:")+64 {
			t.Fatalf("scenario %s has invalid digest %q", scenario, firstDigest)
		}
		if secondDigest, _ := second.Digest(scenario); secondDigest != firstDigest {
			t.Fatalf("scenario %s digest is not stable: %s != %s", scenario, firstDigest, secondDigest)
		}
	}
}

func TestProductionManifestContractsPreserveBaselineSemantics(t *testing.T) {
	t.Parallel()
	registry, err := LoadDir(productionScenarioDir(t), profiles.Registry())
	if err != nil {
		t.Fatal(err)
	}
	for scenario, expectedContracts := range baselineContracts() {
		for profile, expected := range expectedContracts {
			contract, ok := registry.Contract(scenario, profile)
			if !ok {
				t.Errorf("missing contract for %s/%s", scenario, profile)
				continue
			}
			if !reflect.DeepEqual(contract.Baseline, expected.Baseline) {
				t.Errorf("baseline contract changed for %s/%s: got %#v, want %#v", scenario, profile, contract.Baseline, expected.Baseline)
			}
			if !reflect.DeepEqual(contract.Policy, expected.Policy) {
				t.Errorf("policy contract changed for %s/%s: got %#v, want %#v", scenario, profile, contract.Policy, expected.Policy)
			}
		}
	}
}

func TestLoadDirRejectsInvalidManifests(t *testing.T) {
	t.Parallel()
	valid := `id: test
version: 1
evidence_dependencies:
  curl-default: [issuer_ack]
profiles:
  curl-default:
    baseline:
      before: {decision: ACCEPT, reasons: [NO_REVOCATION_CHECK]}
      after: {decision: ACCEPT, reasons: [NO_REVOCATION_CHECK]}
    policy:
      after: {decision: REJECT, reasons: [REVOKED]}
`
	tests := []struct {
		name    string
		content string
		second  string
		want    string
	}{
		{"unknown field", strings.Replace(valid, "version: 1", "version: 1\nunexpected: true", 1), "", "field unexpected not found"},
		{"unknown decision", strings.Replace(valid, "ACCEPT", "MAYBE", 1), "", "unknown decision"},
		{"unknown reason", strings.Replace(valid, "NO_REVOCATION_CHECK", "MAYBE", 1), "", "unknown reason"},
		{"invalid evidence", strings.Replace(valid, "issuer_ack", "future_magic", 1), "", "unknown evidence dependency"},
		{"missing evidence", strings.Replace(valid, "  curl-default: [issuer_ack]\n", "", 1), "", "has no evidence dependencies"},
		{"duplicate scenario", valid, valid, "duplicate scenario"},
		{"duplicate profile", valid + "  curl-default:\n    baseline: {before: {decision: ACCEPT}, after: {decision: ACCEPT}}\n    policy: {after: {decision: REJECT}}\n", "", "mapping key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "first.yaml"), []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.second != "" {
				if err := os.WriteFile(filepath.Join(directory, "second.yaml"), []byte(test.second), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := LoadDir(directory, profiles.Registry())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadDir error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateEnabledProfilesRejectsMissingContract(t *testing.T) {
	t.Parallel()
	registry := New(Manifest{ID: profiles.ScenarioRevokedStaple, Profiles: map[string]Contract{}})
	if err := registry.ValidateEnabledProfiles([]string{"curl-default"}); err == nil {
		t.Fatal("accepted an enabled profile with no scenario contract")
	}
}

func profileNames(implementations []profiles.Profile) []string {
	names := make([]string, 0, len(implementations))
	for _, implementation := range implementations {
		names = append(names, implementation.Name)
	}
	return names
}

func accept(reason profiles.Reason) profiles.Observation {
	return profiles.Observation{Decision: profiles.DecisionAccept, Reason: reason}
}

func reject(reason profiles.Reason) profiles.Observation {
	return profiles.Observation{Decision: profiles.DecisionReject, Reason: reason}
}

func baselineContracts() map[profiles.Scenario]map[string]Contract {
	policy := profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{
		profiles.ReasonRevoked, profiles.ReasonMissingStatus, profiles.ReasonInvalidStatus, profiles.ReasonStaleStatus,
		profiles.ReasonFutureStatus, profiles.ReasonUnknownStatus, profiles.ReasonMissingFreshness,
	}}
	goodThenRevoked := profiles.Expectation{Before: profiles.DecisionAccept, BeforeReasons: []profiles.Reason{profiles.ReasonStatusGood}, After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}}
	noCheck := profiles.Expectation{Before: profiles.DecisionAccept, BeforeReasons: []profiles.Reason{profiles.ReasonNoRevocationCheck}, After: profiles.DecisionAccept, AfterReasons: []profiles.Reason{profiles.ReasonNoRevocationCheck}}
	withPolicy := func(baseline profiles.Expectation) Contract { return Contract{Baseline: baseline, Policy: policy} }
	contracts := func(oracle, curl, hardfail profiles.Expectation) map[string]Contract {
		return map[string]Contract{
			"openssl-ocsp-direct": withPolicy(oracle),
			"crl-check":           withPolicy(oracle),
			"curl-cert-status":    withPolicy(curl),
			"go-hardfail-ocsp":    withPolicy(hardfail),
			"curl-default":        withPolicy(noCheck),
			"go-tls-default":      withPolicy(noCheck),
			"python-requests":     withPolicy(noCheck),
		}
	}
	missing := profiles.Expectation{Before: profiles.DecisionReject, BeforeReasons: []profiles.Reason{profiles.ReasonMissingStatus}, After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonMissingStatus}}
	cachedGood := profiles.Expectation{Before: profiles.DecisionAccept, BeforeReasons: []profiles.Reason{profiles.ReasonStatusGood}, After: profiles.DecisionAccept, AfterReasons: []profiles.Reason{profiles.ReasonStatusGood}}
	curlRevoked := goodThenRevoked
	curlRevoked.AfterReasons = []profiles.Reason{profiles.ReasonRevoked, profiles.ReasonInvalidStatus}
	return map[profiles.Scenario]map[string]Contract{
		profiles.ScenarioRevokedStaple:    contracts(goodThenRevoked, curlRevoked, goodThenRevoked),
		profiles.ScenarioMissingStaple:    contracts(goodThenRevoked, missing, missing),
		profiles.ScenarioCachedGoodStaple: contracts(goodThenRevoked, cachedGood, cachedGood),
	}
}
