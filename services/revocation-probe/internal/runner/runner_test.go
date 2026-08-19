package runner

import (
	"context"
	"errors"
	"testing"
	"time"

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
		Name:   "accepting",
		Method: profiles.MethodNone,
		Probe: func(context.Context, profiles.Target) (profiles.Outcome, error) {
			return profiles.OutcomeAccepted, nil
		},
	}
	result := r.pollOne(context.Background(), p, profiles.Target{}, time.Now())
	if result.Outcome != profiles.OutcomeAccepted || result.Attempts != 2 {
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
		Method: profiles.MethodCRL,
		Probe: func(context.Context, profiles.Target) (profiles.Outcome, error) {
			return profiles.OutcomeError, errors.New("responder unavailable")
		},
	}
	result := r.pollOne(context.Background(), p, profiles.Target{}, time.Now())
	if result.Outcome != profiles.OutcomeError || result.Err == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
