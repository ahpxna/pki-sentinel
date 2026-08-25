package scenarios

import (
	"os"
	"path/filepath"
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
	for scenario, expectedStapling := range map[profiles.Scenario]StaplingMode{
		"revoked_staple":     StaplingOn,
		"missing_staple":     StaplingOff,
		"cached_good_staple": StaplingStale,
	} {
		manifest, ok := first.Manifest(scenario)
		if !ok || manifest.Stapling != expectedStapling {
			t.Errorf("scenario %s execution stapling=%q, want %q", scenario, manifest.Stapling, expectedStapling)
		}
	}
	second, err := LoadDir(productionScenarioDir(t), implementations)
	if err != nil {
		t.Fatalf("reload production manifests: %v", err)
	}
	for _, scenario := range []profiles.Scenario{"revoked_staple", "missing_staple", "cached_good_staple"} {
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
			if !expectationSemanticallyEqual(contract.Baseline, expected.Baseline) {
				t.Errorf("baseline contract changed for %s/%s: got %#v, want %#v", scenario, profile, contract.Baseline, expected.Baseline)
			}
			if !expectationSemanticallyEqual(contract.Policy, expected.Policy) {
				t.Errorf("policy contract changed for %s/%s: got %#v, want %#v", scenario, profile, contract.Policy, expected.Policy)
			}
		}
	}
}

func expectationSemanticallyEqual(got, want profiles.Expectation) bool {
	return got.Before == want.Before &&
		got.After == want.After &&
		reasonSetsEqual(got.BeforeReasons, want.BeforeReasons) &&
		reasonSetsEqual(got.AfterReasons, want.AfterReasons)
}

func reasonSetsEqual(got, want []profiles.Reason) bool {
	if len(got) != len(want) {
		return false
	}
	counts := make(map[profiles.Reason]int, len(got))
	for _, reason := range got {
		counts[reason]++
	}
	for _, reason := range want {
		counts[reason]--
		if counts[reason] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func TestLoadDirRejectsInvalidManifests(t *testing.T) {
	t.Parallel()
	valid := `id: test
version: 1
execution:
  stapling: off
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
		{"missing reasons", strings.Replace(valid, ", reasons: [NO_REVOCATION_CHECK]", "", 1), "", "must declare at least one reason"},
		{"empty reasons", strings.Replace(valid, "[NO_REVOCATION_CHECK]", "[]", 1), "", "must declare at least one reason"},
		{"duplicate reasons", strings.Replace(valid, "[NO_REVOCATION_CHECK]", "[NO_REVOCATION_CHECK, NO_REVOCATION_CHECK]", 1), "", "repeats reason"},
		{"incompatible decision reason", strings.Replace(valid, "decision: ACCEPT, reasons: [NO_REVOCATION_CHECK]", "decision: REJECT, reasons: [NO_REVOCATION_CHECK]", 1), "", "incompatible with reason"},
		{"invalid evidence", strings.Replace(valid, "issuer_ack", "future_magic", 1), "", "unknown evidence dependency"},
		{"missing evidence", strings.Replace(valid, "  curl-default: [issuer_ack]\n", "", 1), "", "has no evidence dependencies"},
		{"empty evidence", strings.Replace(valid, "[issuer_ack]", "[]", 1), "", "empty evidence dependency list"},
		{"orphan evidence contract", strings.Replace(valid, "  curl-default: [issuer_ack]\n", "  curl-default: [issuer_ack]\n  go-tls-default: [issuer_ack]\n", 1), "", "without a contract"},
		{"missing execution", strings.Replace(valid, "execution:\n  stapling: off\n", "", 1), "", "invalid execution.stapling"},
		{"staple dependency without staple execution", strings.Replace(valid, "issuer_ack", "staple_published", 1), "", "requires staple_published"},
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

func TestCanonicalDigestTreatsReasonAndDependencyListsAsSets(t *testing.T) {
	t.Parallel()
	first := yamlManifest{
		ID: "stable", Version: Version, Execution: yamlExecution{Stapling: StaplingOn},
		EvidenceDependencies: map[string][]EvidenceDependency{"curl-default": {EvidenceStaplePublished, EvidenceIssuerAck}},
		Profiles: map[string]yamlProfileContract{"curl-default": {
			Baseline: yamlBaseline{
				Before: yamlExpectation{Decision: "ACCEPT", Reasons: []string{"NO_REVOCATION_CHECK"}},
				After:  yamlExpectation{Decision: "REJECT", Reasons: []string{"INVALID_STATUS", "REVOKED"}},
			},
			Policy: yamlPolicy{After: yamlExpectation{Decision: "REJECT", Reasons: []string{"REVOKED", "INVALID_STATUS"}}},
		}},
	}
	second := first
	second.EvidenceDependencies = map[string][]EvidenceDependency{"curl-default": {EvidenceIssuerAck, EvidenceStaplePublished}}
	contract := second.Profiles["curl-default"]
	contract.Baseline.After.Reasons = []string{"REVOKED", "INVALID_STATUS"}
	contract.Policy.After.Reasons = []string{"INVALID_STATUS", "REVOKED"}
	second.Profiles = map[string]yamlProfileContract{"curl-default": contract}

	normalizeManifest(&first)
	normalizeManifest(&second)
	firstDigest, err := canonicalDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := canonicalDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("semantic-equivalent manifests have different digests: %s != %s", firstDigest, secondDigest)
	}
}

func TestValidateEnabledProfilesRequiresPublicationProducer(t *testing.T) {
	t.Parallel()
	registry := &Registry{
		manifests: map[profiles.Scenario]Manifest{"test": {
			ID: "test",
			Profiles: map[string]Contract{
				"curl-default": {Baseline: profiles.Expectation{After: profiles.DecisionReject}},
			},
			EvidenceDependencies: map[string][]EvidenceDependency{"curl-default": {EvidenceOCSPPublished}},
		}},
		implementations: knownProfiles(profiles.Registry()),
	}
	if err := registry.ValidateEnabledProfiles([]string{"curl-default"}); err == nil || !strings.Contains(err.Error(), "no enabled OCSP status oracle") {
		t.Fatalf("ValidateEnabledProfiles error=%v, want missing publication producer", err)
	}
}

func TestValidateEnabledProfilesRejectsMissingContract(t *testing.T) {
	t.Parallel()
	registry := New(Manifest{ID: "revoked_staple", Profiles: map[string]Contract{}})
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
		"revoked_staple":     contracts(goodThenRevoked, curlRevoked, goodThenRevoked),
		"missing_staple":     contracts(goodThenRevoked, missing, missing),
		"cached_good_staple": contracts(goodThenRevoked, cachedGood, cachedGood),
	}
}
