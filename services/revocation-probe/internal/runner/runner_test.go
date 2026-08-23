package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/canary"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

func TestPollOneHonorsMaxAttempts(t *testing.T) {
	r := &Runner{Config: &config.Config{
		PollInterval: time.Millisecond,
		MaxWait:      time.Second,
		MaxAttempts:  2,
	}}
	p := profiles.Profile{
		Name:   "unexpected-accept",
		Role:   profiles.RoleClientExecutor,
		Method: profiles.MethodOCSPStapled,
		Expectations: map[profiles.Scenario]profiles.Expectation{
			profiles.ScenarioRevokedStaple: {Before: profiles.DecisionAccept, After: profiles.DecisionReject},
		},
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
	}}
	p := profiles.Profile{
		Name:   "broken",
		Role:   profiles.RoleStatusOracle,
		Method: profiles.MethodCRL,
		Expectations: map[profiles.Scenario]profiles.Expectation{
			profiles.ScenarioRevokedStaple: {Before: profiles.DecisionAccept, After: profiles.DecisionReject},
		},
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
