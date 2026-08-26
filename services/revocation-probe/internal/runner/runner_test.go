package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/scenarios"
)

func testScenarios(names ...string) *scenarios.Registry {
	contracts := make(map[string]scenarios.Contract, len(names))
	for _, name := range names {
		contracts[name] = scenarios.Contract{
			Baseline: profiles.Expectation{Before: profiles.DecisionAccept, After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}},
			Policy:   profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}},
		}
	}
	dependencies := make(map[string][]scenarios.EvidenceDependency, len(names))
	for _, name := range names {
		dependencies[name] = []scenarios.EvidenceDependency{scenarios.EvidenceIssuerAck}
	}
	return scenarios.New(scenarios.Manifest{ID: profiles.Scenario("test"), Digest: "sha256:test", Stapling: scenarios.StaplingOn, Profiles: contracts, EvidenceDependencies: dependencies})
}

func TestPollOneHonorsMaxAttempts(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond,
		MaxWait:      time.Second,
		MaxAttempts:  2,
	}, Scenario: profiles.Scenario("test"), Scenarios: testScenarios("unexpected-accept")}
	p := profiles.Profile{
		Name:   "unexpected-accept",
		Role:   profiles.RoleClientExecutor,
		Method: profiles.MethodOCSPStapled,
		Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{Decision: profiles.DecisionAccept, Reason: profiles.ReasonStatusGood}, nil
		},
	}
	target := profiles.Target{Scenario: profiles.Scenario("test")}
	result := r.pollOne(context.Background(), p, target, time.Now())
	if result.Decision != profiles.DecisionAccept || result.ExpectationMet || result.Attempts != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestPollOneDoesNotConvertHarnessErrorToSoftFail(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond,
		MaxWait:      time.Second,
		MaxAttempts:  1,
	}, Scenario: profiles.Scenario("test"), Scenarios: testScenarios("broken")}
	p := profiles.Profile{
		Name:   "broken",
		Role:   profiles.RoleStatusOracle,
		Method: profiles.MethodCRL,
		Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure}, errors.New("invalid harness configuration")
		},
	}
	target := profiles.Target{Scenario: profiles.Scenario("test")}
	result := r.pollOne(context.Background(), p, target, time.Now())
	if result.Decision != profiles.DecisionHarnessError || result.Err == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunOnceRejectsUnknownScenarioBeforeIssuing(t *testing.T) {
	r := &Runner{Scenario: profiles.Scenario("missing"), Scenarios: testScenarios("unused")}
	if report, err := r.RunOnce(context.Background()); err == nil || report != nil {
		t.Fatalf("RunOnce report=%v err=%v, want missing-scenario failure before issuer use", report, err)
	}
}

func TestRunOnceRejectsInvalidManifestStaplingBeforeIssuing(t *testing.T) {
	scenarioID := profiles.Scenario("invalid")
	r := &Runner{Scenario: scenarioID, Scenarios: scenarios.New(scenarios.Manifest{ID: scenarioID, Digest: "sha256:test", Stapling: scenarios.StaplingMode("maybe")})}
	if report, err := r.RunOnce(context.Background()); err == nil || report != nil {
		t.Fatalf("RunOnce report=%v err=%v, want invalid-stapling failure before issuer use", report, err)
	}
}

func TestRunOnceRequiresEnabledOracleAndClientBeforeIssuing(t *testing.T) {
	for _, test := range []struct {
		name     string
		profiles []profiles.Profile
	}{
		{name: "client only", profiles: []profiles.Profile{{Name: "client", Role: profiles.RoleClientExecutor}}},
		{name: "oracle only", profiles: []profiles.Profile{{Name: "oracle", Role: profiles.RoleStatusOracle}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := test.profiles[0].Name
			r := &Runner{
				Config:    &config.Config{Profiles: []config.ProfileConfig{{Name: name, Enabled: true, Timeout: time.Second}}},
				Profiles:  test.profiles,
				Scenario:  "test",
				Scenarios: testScenarios(name),
			}
			report, err := r.RunOnce(context.Background())
			if err == nil || report != nil {
				t.Fatalf("RunOnce report=%v err=%v, want role validation before issuer use", report, err)
			}
		})
	}
}

func TestPreflightRetainsBeforeObservationEvidence(t *testing.T) {
	r := &Runner{Config: &config.Config{Profiles: []config.ProfileConfig{{Name: "client", Enabled: true, Timeout: time.Second}}}, Scenarios: testScenarios("client")}
	r.Profiles = []profiles.Profile{{
		Name: "client", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone,
		Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{
				Decision: profiles.DecisionAccept, Reason: profiles.ReasonStatusGood,
				Evidence: profiles.CommandEvidence{RawArtifacts: []profiles.RawArtifact{{Name: "before.txt", Data: "reachable"}}},
			}, nil
		},
	}}
	manifest, _ := r.Scenarios.Manifest("test")
	contract := manifest.Profiles["client"]
	contract.Baseline.Before = profiles.DecisionAccept
	contract.Baseline.BeforeReasons = []profiles.Reason{profiles.ReasonStatusGood}
	manifest.Profiles["client"] = contract
	r.Scenarios = scenarios.New(manifest)

	results, _, err := r.preflight(context.Background(), profiles.Target{Scenario: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].ExpectationMet || results[0].ObservedAt.IsZero() {
		t.Fatalf("unexpected preflight result: %#v", results)
	}
	if len(results[0].Evidence.RawArtifacts) != 1 || results[0].Evidence.RawArtifacts[0].Data != "reachable" {
		t.Fatalf("preflight evidence was discarded: %#v", results[0].Evidence)
	}
}

func TestPollClientsWaitsForManifestEvidenceDependencies(t *testing.T) {
	scenarioID := profiles.Scenario("custom_manifest_scenario")
	contracts := map[string]scenarios.Contract{
		"independent":    {Baseline: profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}}, Policy: profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}}},
		"manifest-gated": {Baseline: profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}}, Policy: profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}}},
	}
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond,
		MaxWait:      time.Second,
		MaxAttempts:  1,
		Profiles: []config.ProfileConfig{
			{Name: "independent", Enabled: true, Timeout: time.Second},
			{Name: "manifest-gated", Enabled: true, Timeout: time.Second},
		},
	}, Scenario: scenarioID, Scenarios: scenarios.New(scenarios.Manifest{ID: scenarioID, Digest: "sha256:test", Stapling: scenarios.StaplingOn, Profiles: contracts, EvidenceDependencies: map[string][]scenarios.EvidenceDependency{
		"independent":    {scenarios.EvidenceIssuerAck},
		"manifest-gated": {scenarios.EvidenceStaplePublished},
	}})}
	independentStarted := make(chan struct{})
	clientProfiles := []profiles.Profile{
		{Name: "independent", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone, Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			close(independentStarted)
			return profiles.Observation{Decision: profiles.DecisionReject, Reason: profiles.ReasonRevoked}, nil
		}},
		{Name: "manifest-gated", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone, Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{Decision: profiles.DecisionReject, Reason: profiles.ReasonRevoked}, nil
		}},
	}
	r.Profiles = clientProfiles
	issuerAck := newEvidenceBarrier()
	issuerAck.satisfy(time.Now())
	staple := newEvidenceBarrier()
	done := make(chan []profiles.Result, 1)
	go func() {
		done <- r.pollClients(context.Background(), profiles.Target{Scenario: scenarioID}, time.Now(), map[scenarios.EvidenceDependency]*evidenceBarrier{
			scenarios.EvidenceIssuerAck:       issuerAck,
			scenarios.EvidenceStaplePublished: staple,
		})
	}()
	select {
	case <-independentStarted:
	case <-time.After(time.Second):
		t.Fatal("independent client waited for staple publication")
	}
	select {
	case <-done:
		t.Fatal("manifest-gated client ran before staple publication")
	default:
	}
	staple.satisfy(time.Now())
	if results := <-done; len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
}

func TestValidatePreflightAgeUsesProbeStartBoundary(t *testing.T) {
	now := time.Now()
	if err := validatePreflightAge(map[string]time.Time{"remote-client": now.Add(-3 * time.Second)}, now, 2*time.Second); err == nil {
		t.Fatal("preflight accepted a probe whose start predates the freshness bound")
	}
	if err := validatePreflightAge(map[string]time.Time{"remote-client": now.Add(-time.Second)}, now, 2*time.Second); err != nil {
		t.Fatalf("fresh probe start rejected: %v", err)
	}
}

func TestTimelineDerivesSeparatePropagationBoundaries(t *testing.T) {
	ack := time.Now()
	timeline := newTimeline(ack.Add(-time.Millisecond), ack)
	timeline.setOCSPOracleRevoked(ack.Add(time.Second))
	timeline.setCRLOracleRevoked(ack.Add(2 * time.Second))
	timeline.setStapleSourceRevoked(ack.Add(3 * time.Second))
	timeline.setStaplePublished(ack.Add(3500 * time.Millisecond))
	timeline.derive()
	if timeline.OCSPOraclePropagationLatency != time.Second || timeline.CRLOraclePropagationLatency != 2*time.Second || timeline.StapleSourcePropagationLatency != 3*time.Second || timeline.StapleDistributionLatency != 500*time.Millisecond {
		t.Fatalf("unexpected derived timeline: %#v", timeline)
	}
}

func TestPollOneBoundsAttemptByRemainingMaxWait(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Second,
		MaxWait:      30 * time.Millisecond,
		MaxAttempts:  10,
		Profiles:     []config.ProfileConfig{{Name: "slow", Enabled: true, Timeout: time.Second}},
	}, Scenario: "test", Scenarios: testScenarios("slow")}
	p := profiles.Profile{
		Name: "slow", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone,
		Probe: func(ctx context.Context, _ profiles.Target) (profiles.Observation, error) {
			<-ctx.Done()
			return profiles.Observation{}, ctx.Err()
		},
	}
	started := time.Now()
	result := r.pollOne(context.Background(), p, profiles.Target{Scenario: "test"}, time.Now())
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("pollOne exceeded MaxWait by profile timeout: %s", elapsed)
	}
	if result.Decision != profiles.DecisionHarnessError || result.Err == "" {
		t.Fatalf("unexpected bounded-timeout result: %#v", result)
	}
}

func TestSortResultsIsDeterministic(t *testing.T) {
	results := []profiles.Result{{Profile: "z"}, {Profile: "a"}, {Profile: "m"}}
	sortResults(results)
	if results[0].Profile != "a" || results[1].Profile != "m" || results[2].Profile != "z" {
		t.Fatalf("results are not sorted deterministically: %#v", results)
	}
}

func TestPublicationEvidenceFailsClosedUntilRevokedIsConfirmed(t *testing.T) {
	if _, err := publicationEvidence(profiles.MethodOCSPDirect, []profiles.Result{{
		Profile: "oracle", Method: profiles.MethodOCSPDirect,
		Decision: profiles.DecisionInconclusive, Reason: profiles.ReasonNetworkFailure,
		ExpectationMet: false,
	}}); err == nil {
		t.Fatal("publicationEvidence accepted a completed oracle without REJECT/REVOKED evidence")
	}
	at := time.Now()
	got, err := publicationEvidence(profiles.MethodOCSPDirect, []profiles.Result{{
		Profile: "oracle", Method: profiles.MethodOCSPDirect,
		Decision: profiles.DecisionReject, Reason: profiles.ReasonRevoked,
		ExpectationMet: false, DecisionAt: at,
	}})
	if err != nil || !got.Equal(at) {
		t.Fatalf("publicationEvidence got=%v err=%v, want %v", got, err, at)
	}
}

func TestEvidenceBarrierFailurePreventsClientProbe(t *testing.T) {
	scenarioID := profiles.Scenario("dependency_failure")
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond, MaxWait: time.Second, MaxAttempts: 1,
		Profiles: []config.ProfileConfig{{Name: "client", Enabled: true, Timeout: time.Second}},
	}, Scenario: scenarioID, Scenarios: scenarios.New(scenarios.Manifest{
		ID: scenarioID, Digest: "sha256:test", Stapling: scenarios.StaplingOn,
		Profiles: map[string]scenarios.Contract{"client": {
			Baseline: profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}},
			Policy:   profiles.Expectation{After: profiles.DecisionReject, AfterReasons: []profiles.Reason{profiles.ReasonRevoked}},
		}},
		EvidenceDependencies: map[string][]scenarios.EvidenceDependency{"client": {scenarios.EvidenceOCSPPublished}},
	})}
	called := false
	r.Profiles = []profiles.Profile{{Name: "client", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone, Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
		called = true
		return profiles.Observation{Decision: profiles.DecisionReject, Reason: profiles.ReasonRevoked}, nil
	}}}
	barrier := newEvidenceBarrier()
	barrier.fail(errors.New("oracle timed out"))
	results := r.pollClients(context.Background(), profiles.Target{Scenario: scenarioID}, time.Now(), map[scenarios.EvidenceDependency]*evidenceBarrier{
		scenarios.EvidenceOCSPPublished: barrier,
	})
	if called {
		t.Fatal("dependent client executed after unsatisfied publication evidence")
	}
	if len(results) != 1 || results[0].Decision != profiles.DecisionHarnessError || results[0].Err == "" {
		t.Fatalf("unexpected dependency failure result: %#v", results)
	}
}

func TestPreflightRunsEnabledProfilesConcurrently(t *testing.T) {
	const delay = 80 * time.Millisecond
	r := &Runner{Config: &config.Config{Profiles: []config.ProfileConfig{
		{Name: "a", Enabled: true, Timeout: time.Second},
		{Name: "b", Enabled: true, Timeout: time.Second},
	}}, Scenarios: testScenarios("a", "b")}
	probe := func(context.Context, profiles.Target) (profiles.Observation, error) {
		time.Sleep(delay)
		return profiles.Observation{Decision: profiles.DecisionAccept, Reason: profiles.ReasonStatusGood}, nil
	}
	r.Profiles = []profiles.Profile{
		{Name: "a", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone, Probe: probe},
		{Name: "b", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone, Probe: probe},
	}
	manifest, _ := r.Scenarios.Manifest("test")
	for _, name := range []string{"a", "b"} {
		contract := manifest.Profiles[name]
		contract.Baseline.Before = profiles.DecisionAccept
		contract.Baseline.BeforeReasons = []profiles.Reason{profiles.ReasonStatusGood}
		manifest.Profiles[name] = contract
	}
	r.Scenarios = scenarios.New(manifest)
	started := time.Now()
	results, _, err := r.preflight(context.Background(), profiles.Target{Scenario: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
	if elapsed := time.Since(started); elapsed >= 150*time.Millisecond {
		t.Fatalf("preflight appears sequential: elapsed=%s", elapsed)
	}
}

func TestValidatePreflightAgeRejectsStaleObservation(t *testing.T) {
	now := time.Now()
	if err := validatePreflightAge(map[string]time.Time{"fresh": now.Add(-time.Second)}, now, 2*time.Second); err != nil {
		t.Fatalf("fresh observation rejected: %v", err)
	}
	if err := validatePreflightAge(map[string]time.Time{"stale": now.Add(-3 * time.Second)}, now, 2*time.Second); err == nil {
		t.Fatal("stale preflight observation accepted")
	}
}

func TestRunOnceRejectsZeroEnabledProfilesBeforeIssuing(t *testing.T) {
	r := &Runner{
		Config:    &config.Config{Profiles: []config.ProfileConfig{{Name: "client", Enabled: false, Timeout: time.Second}}},
		Scenario:  profiles.Scenario("test"),
		Scenarios: testScenarios("client"),
	}
	if report, err := r.RunOnce(context.Background()); err == nil || report != nil {
		t.Fatalf("RunOnce report=%v err=%v, want zero-profile failure before issuer use", report, err)
	}
}
