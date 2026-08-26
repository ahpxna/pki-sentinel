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
	r := &Runner{
		Config:   &config.Config{Profiles: []config.ProfileConfig{{Name: "unused", Enabled: true, Timeout: time.Second}}},
		Scenario: profiles.Scenario("missing"), Scenarios: testScenarios("unused"),
	}
	if report, err := r.RunOnce(context.Background()); err == nil || report != nil {
		t.Fatalf("RunOnce report=%v err=%v, want missing-scenario failure before issuer use", report, err)
	}
}

func TestRunOnceRejectsInvalidManifestStaplingBeforeIssuing(t *testing.T) {
	scenarioID := profiles.Scenario("invalid")
	r := &Runner{
		Config:   &config.Config{Profiles: []config.ProfileConfig{{Name: "unused", Enabled: true, Timeout: time.Second}}},
		Scenario: scenarioID, Scenarios: scenarios.New(scenarios.Manifest{ID: scenarioID, Digest: "sha256:test", Stapling: scenarios.StaplingMode("maybe")}),
	}
	if report, err := r.RunOnce(context.Background()); err == nil || report != nil {
		t.Fatalf("RunOnce report=%v err=%v, want invalid-stapling failure before issuer use", report, err)
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

	results, err := r.preflight(context.Background(), profiles.Target{Scenario: "test"})
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
	stapleReady := make(chan struct{})
	done := make(chan []profiles.Result, 1)
	go func() {
		done <- r.pollClients(context.Background(), profiles.Target{Scenario: scenarioID}, time.Now(), map[scenarios.EvidenceDependency]evidenceBarrier{
			scenarios.EvidenceIssuerAck:       {ready: closedEvidence()},
			scenarios.EvidenceStaplePublished: {ready: stapleReady},
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
	close(stapleReady)
	if results := <-done; len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
}

func TestTimelineDerivesSeparatePropagationBoundaries(t *testing.T) {
	ack := time.Now().UTC()
	timeline := Timeline{
		RevokeAckAt: ack, OCSPFirstRevoked: ack.Add(time.Second), CRLFirstRevoked: ack.Add(2 * time.Second), StaplePublished: ack.Add(3 * time.Second),
	}
	timeline.derive()
	if timeline.OCSPPropagationLatency != time.Second || timeline.CRLPropagationLatency != 2*time.Second || timeline.StapleDistributionLatency != 3*time.Second {
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

func TestPublicationErrorFailsClosedUntilRevocationIsObserved(t *testing.T) {
	method := profiles.MethodOCSPDirect
	if err := publicationError(method, nil); err == nil {
		t.Fatal("empty oracle result set established publication")
	}
	if err := publicationError(method, []profiles.Result{{
		Profile: "oracle", Method: method, Decision: profiles.DecisionInconclusive,
		Reason: profiles.ReasonNetworkFailure, ExpectationMet: false,
	}}); err == nil {
		t.Fatal("inconclusive oracle result established publication")
	}
	if err := publicationError(method, []profiles.Result{{
		Profile: "oracle", Method: method, Decision: profiles.DecisionHarnessError,
		Reason: profiles.ReasonHarnessFailure, Err: "executor unavailable",
	}}); err == nil {
		t.Fatal("harness error established publication")
	}
	if err := publicationError(method, []profiles.Result{{
		Profile: "oracle", Method: method, Decision: profiles.DecisionReject,
		Reason: profiles.ReasonRevoked, ExpectationMet: true,
	}}); err != nil {
		t.Fatalf("revoked oracle result did not establish publication: %v", err)
	}
}

func TestWaitForEvidencePropagatesPublicationFailure(t *testing.T) {
	scenarioID := profiles.Scenario("publication_failure")
	r := &Runner{Scenarios: scenarios.New(scenarios.Manifest{
		ID: scenarioID,
		EvidenceDependencies: map[string][]scenarios.EvidenceDependency{
			"client": {scenarios.EvidenceOCSPPublished},
		},
	})}
	ready := make(chan struct{})
	publicationErr := errors.New("publication not established")
	close(ready)
	err := r.waitForEvidence(context.Background(), scenarioID, "client", map[scenarios.EvidenceDependency]evidenceBarrier{
		scenarios.EvidenceOCSPPublished: {ready: ready, err: func() error { return publicationErr }},
	})
	if err == nil || !errors.Is(err, publicationErr) {
		t.Fatalf("waitForEvidence error=%v, want publication failure", err)
	}
}
