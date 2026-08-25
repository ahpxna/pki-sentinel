package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/canary"
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
	return scenarios.New(scenarios.Manifest{ID: profiles.ScenarioRevokedStaple, Digest: "sha256:test", Profiles: contracts})
}

func TestPollOneHonorsMaxAttempts(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond,
		MaxWait:      time.Second,
		MaxAttempts:  2,
	}, Scenarios: testScenarios("unexpected-accept")}
	p := profiles.Profile{
		Name:   "unexpected-accept",
		Role:   profiles.RoleClientExecutor,
		Method: profiles.MethodOCSPStapled,
		Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{Decision: profiles.DecisionAccept, Reason: profiles.ReasonStatusGood}, nil
		},
	}
	target := profiles.Target{Scenario: profiles.ScenarioRevokedStaple}
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
	}, Scenarios: testScenarios("broken")}
	p := profiles.Profile{
		Name:   "broken",
		Role:   profiles.RoleStatusOracle,
		Method: profiles.MethodCRL,
		Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure}, errors.New("invalid harness configuration")
		},
	}
	target := profiles.Target{Scenario: profiles.ScenarioRevokedStaple}
	result := r.pollOne(context.Background(), p, target, time.Now())
	if result.Decision != profiles.DecisionHarnessError || result.Err == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestScenarioForStapling(t *testing.T) {
	cases := map[canary.StaplingMode]profiles.Scenario{
		canary.StaplingOn:    profiles.ScenarioRevokedStaple,
		canary.StaplingOff:   profiles.ScenarioMissingStaple,
		canary.StaplingStale: profiles.ScenarioCachedGoodStaple,
	}
	for mode, expected := range cases {
		if got := scenarioForStapling(mode); got != expected {
			t.Errorf("mode %s: got %s, expected %s", mode, got, expected)
		}
	}
}

func TestPollClientsDoesNotWaitForStapleBeforeRunningIndependentClient(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond,
		MaxWait:      time.Second,
		MaxAttempts:  1,
		Profiles: []config.ProfileConfig{
			{Name: "independent", Enabled: true, Timeout: time.Second},
			{Name: "stapled", Enabled: true, Timeout: time.Second},
		},
	}, Stapling: canary.StaplingOn, Scenarios: testScenarios("independent", "stapled")}
	independentStarted := make(chan struct{})
	clientProfiles := []profiles.Profile{
		{Name: "independent", Role: profiles.RoleClientExecutor, Method: profiles.MethodNone, Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			close(independentStarted)
			return profiles.Observation{Decision: profiles.DecisionReject, Reason: profiles.ReasonRevoked}, nil
		}},
		{Name: "stapled", Role: profiles.RoleClientExecutor, Method: profiles.MethodOCSPStapled, Probe: func(context.Context, profiles.Target) (profiles.Observation, error) {
			return profiles.Observation{Decision: profiles.DecisionReject, Reason: profiles.ReasonRevoked}, nil
		}},
	}
	r.Profiles = clientProfiles
	stapleReady := make(chan struct{})
	done := make(chan []profiles.Result, 1)
	go func() {
		done <- r.pollClients(context.Background(), profiles.Target{Scenario: profiles.ScenarioRevokedStaple}, time.Now(), stapleReady, func() error { return nil })
	}()
	select {
	case <-independentStarted:
	case <-time.After(time.Second):
		t.Fatal("independent client waited for staple publication")
	}
	select {
	case <-done:
		t.Fatal("stapled client ran before staple publication")
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
