// Package runner implements the revocation-probe cycle: issue a canary
// cert, start an ephemeral TLS server, run a pre-flight guard, revoke,
// poll every enabled profile in parallel until it detects rejection or
// times out, then tear down and emit metrics.
package runner

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/canary"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/issuer"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/metrics"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

// Runner ties together the issuer, canary server, and profile registry.
type Runner struct {
	Issuer   *issuer.Client
	Config   *config.Config
	Profiles []profiles.Profile
	Stapling canary.StaplingMode

	OCSPURL string
	CRLURL  string
	Domain  string // e.g. "internal" — canary hostnames are <uuid>.canary.<Domain>
	// CanaryBindHost and CanaryConnectHost are set only when profiles execute
	// in separate containers. The zero values preserve loopback-only local
	// canaries and direct in-process profile execution.
	CanaryBindHost    string
	CanaryConnectHost string
}

// CycleReport is the structured JSON summary of one cycle (used by
// `probe run --once --output json` and the integration test).
type CycleReport struct {
	CycleID     string            `json:"cycle_id"`
	Scenario    profiles.Scenario `json:"scenario"`
	RevokeAckAt time.Time         `json:"revoke_ack_at"`
	Results     []profiles.Result `json:"results"`
	Error       string            `json:"error,omitempty"`
}

// RunOnce executes exactly one probe cycle.
func (r *Runner) RunOnce(ctx context.Context) (*CycleReport, error) {
	cycleID := uuid.New().String()[:8]
	hostname := fmt.Sprintf("canary-%s.canary.%s", cycleID, r.Domain)

	log.Printf("[cycle %s] issuing canary cert for %s", cycleID, hostname)
	cert, err := r.Issuer.IssueCanary(ctx, hostname)
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("runner: issuing canary: %w", err)
	}
	metrics.CertNotAfter.Set(float64(cert.Cert.NotAfter.Unix()))
	scenario := scenarioForStapling(r.Stapling)

	var staple []byte
	if r.Stapling == canary.StaplingOn || r.Stapling == canary.StaplingStale {
		// StaplingStale fetches the OCSP response BEFORE revocation and
		// keeps serving that same stale "good" response after revocation —
		// exactly how an attacker would extend a compromised cert's
		// perceived validity.
		var status int
		staple, status, err = r.Issuer.FetchOCSPResponse(ctx, r.OCSPURL, cert.Cert, cert.IssuerCert)
		ocspErr := err
		if ocspErr != nil {
			return nil, fmt.Errorf("runner: fetching pre-revocation OCSP staple: %w", ocspErr)
		}
		if status != ocsp.Good {
			return nil, fmt.Errorf("runner: pre-revocation OCSP status=%d, expected good", status)
		}
		log.Printf("[cycle %s] pre-revocation OCSP status for staple: good", cycleID)
	}

	// Send the complete chain in the TLS handshake. Strict stapling clients
	// such as curl/OpenSSL need the intermediate certificate to locate and
	// verify the OCSP response signer; a leaf-only handshake fails before it
	// can evaluate the otherwise valid response.
	tlsChainPEM := []byte(cert.CertPEM + "\n" + cert.ChainPEM)
	bindHost := r.CanaryBindHost
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	srv, err := canary.StartOn(bindHost, hostname, tlsChainPEM, []byte(cert.KeyPEM), staple)
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("runner: starting canary server: %w", err)
	}
	defer srv.Close()

	target := profiles.Target{
		Host:              hostname,
		ConnectHost:       r.CanaryConnectHost,
		Port:              srv.Port,
		CAChainPEM:        cert.ChainPEM,
		IssuerPEM:         cert.IssuerPEM,
		OCSPURL:           r.OCSPURL,
		CRLURL:            r.CRLURL,
		CertificateSerial: cert.SerialNumber,
		Scenario:          scenario,
	}

	// Pre-flight validates each scenario-specific BEFORE contract. A strict
	// client may legitimately reject a missing status before revocation.
	log.Printf("[cycle %s] pre-flight: verifying all profiles can reach the canary", cycleID)
	if err := r.preflight(ctx, target); err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return &CycleReport{CycleID: cycleID, Scenario: scenario, Error: err.Error()}, err
	}

	tReq, tResp, err := r.Issuer.Revoke(ctx, cert.SerialNumber)
	_ = tReq
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("runner: revoking canary: %w", err)
	}
	revokeAckAt := tResp
	log.Printf("[cycle %s] revoked serial=%s at %s", cycleID, cert.SerialNumber, revokeAckAt.Format(time.RFC3339))

	if r.Stapling == canary.StaplingOn {
		if err := r.refreshRevokedStaple(ctx, srv, cert); err != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return nil, err
		}
	}

	results := r.pollAll(ctx, target, revokeAckAt)
	for _, result := range results {
		if result.Decision == profiles.DecisionHarnessError || result.Err != "" {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			report := &CycleReport{CycleID: cycleID, Scenario: scenario, RevokeAckAt: revokeAckAt, Results: results}
			return report, fmt.Errorf("runner: profile %s failed: %s", result.Profile, result.Err)
		}
		if !result.ExpectationMet {
			metrics.CycleTotal.WithLabelValues("regression").Inc()
			report := &CycleReport{CycleID: cycleID, Scenario: scenario, RevokeAckAt: revokeAckAt, Results: results}
			return report, fmt.Errorf("runner: security regression: profile %s produced %s/%s; expected %s", result.Profile, result.Decision, result.Reason, result.ExpectedDecision)
		}
	}

	metrics.LastCycleTimestamp.Set(float64(time.Now().Unix()))
	metrics.CycleTotal.WithLabelValues("ok").Inc()

	return &CycleReport{CycleID: cycleID, Scenario: scenario, RevokeAckAt: revokeAckAt, Results: results}, nil
}

func scenarioForStapling(mode canary.StaplingMode) profiles.Scenario {
	switch mode {
	case canary.StaplingOff:
		return profiles.ScenarioMissingStaple
	case canary.StaplingStale:
		return profiles.ScenarioCachedGoodStaple
	default:
		return profiles.ScenarioRevokedStaple
	}
}

func (r *Runner) refreshRevokedStaple(ctx context.Context, srv *canary.Server, cert *issuer.CanaryCert) error {
	deadline := time.Now().Add(r.Config.MaxWait)
	for {
		staple, status, err := r.Issuer.FetchOCSPResponse(ctx, r.OCSPURL, cert.Cert, cert.IssuerCert)
		if err == nil && status == ocsp.Revoked {
			srv.SetOCSPStaple(staple)
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("runner: waiting for revoked OCSP staple: %w", err)
			}
			return fmt.Errorf("runner: waiting for revoked OCSP staple: last status=%d", status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.Config.PollInterval):
		}
	}
}

// preflight runs every enabled profile once before revocation and validates
// its scenario-specific contract. A strict stapling client is expected to
// reject a missing staple even when the certificate itself is still good.
func (r *Runner) preflight(ctx context.Context, target profiles.Target) error {
	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, r.Config.TimeoutFor(p.Name))
		observation, err := p.Probe(pctx, target)
		cancel()
		if err != nil {
			return fmt.Errorf("preflight: profile %s errored: %w", p.Name, err)
		}
		expectation, ok := p.Expected(target.Scenario)
		if !ok {
			return fmt.Errorf("preflight: profile %s has no expectation for scenario %s", p.Name, target.Scenario)
		}
		if !expectation.MatchesBefore(observation) {
			return fmt.Errorf("preflight: profile %s produced %s/%s, expected %s/%v for scenario %s", p.Name, observation.Decision, observation.Reason, expectation.Before, expectation.BeforeReasons, target.Scenario)
		}
	}
	return nil
}

// pollAll confirms revocation through status oracles before executing client
// profiles. This prevents an early client ACCEPT from being recorded before
// the CA status channels actually acknowledge the revocation.
func (r *Runner) pollAll(ctx context.Context, target profiles.Target, revokedAt time.Time) []profiles.Result {
	oracles := r.pollRole(ctx, profiles.RoleStatusOracle, target, revokedAt)
	for _, result := range oracles {
		if !result.ExpectationMet || result.Decision == profiles.DecisionHarnessError {
			return oracles
		}
	}
	clients := r.pollRole(ctx, profiles.RoleClientExecutor, target, revokedAt)
	return append(oracles, clients...)
}

func (r *Runner) pollRole(ctx context.Context, role profiles.Role, target profiles.Target, revokedAt time.Time) []profiles.Result {
	var wg sync.WaitGroup
	results := make([]profiles.Result, 0, len(r.Profiles))
	var mu sync.Mutex

	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) || p.Role != role {
			continue
		}
		wg.Add(1)
		go func(p profiles.Profile) {
			defer wg.Done()
			res := r.pollOne(ctx, p, target, revokedAt)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return results
}

func (r *Runner) pollOne(ctx context.Context, p profiles.Profile, target profiles.Target, revokedAt time.Time) profiles.Result {
	deadline := time.Now().Add(r.Config.MaxWait)
	attempts := 0
	stapling := string(r.Stapling)
	var lastErr error
	lastObservation := profiles.Observation{Decision: profiles.DecisionInconclusive, Reason: profiles.ReasonHarnessFailure}
	expectation, ok := p.Expected(target.Scenario)
	if !ok {
		return profiles.Result{
			Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
			Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure,
			CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
			Err: fmt.Sprintf("profile has no expectation for scenario %s", target.Scenario),
		}
	}

	for {
		attempts++
		probeCtx, cancel := context.WithTimeout(ctx, r.Config.TimeoutFor(p.Name))
		observation, err := p.Probe(probeCtx, target)
		cancel()
		if err != nil {
			observation.Decision = profiles.DecisionHarnessError
			observation.Reason = profiles.ReasonHarnessFailure
		}
		lastObservation = observation
		now := time.Now()

		if expectation.MatchesAfter(observation) {
			dur := now.Sub(revokedAt)
			metrics.RecordObservation(p.Name, string(p.Role), string(p.Method), string(target.Scenario), string(observation.Decision), string(observation.Reason))
			if observation.Decision == profiles.DecisionReject && observation.Reason == profiles.ReasonRevoked {
				metrics.DetectionSeconds.WithLabelValues(p.Name, string(p.Method), stapling).Observe(dur.Seconds())
				metrics.DetectedTotal.WithLabelValues(p.Name, string(p.Method), stapling).Inc()
			}
			return profiles.Result{
				Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
				Decision: observation.Decision, Reason: observation.Reason,
				ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, ExpectationMet: true,
				CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
				DecisionAt: now, DecisionLatency: dur, Attempts: attempts, Evidence: observation.Evidence,
			}
		}
		if observation.Decision == profiles.DecisionHarnessError {
			lastErr = err
			log.Printf("poll: profile %s error (attempt %d): %v", p.Name, attempts, err)
		}

		if time.Now().After(deadline) || (r.Config.MaxAttempts > 0 && attempts >= r.Config.MaxAttempts) {
			metrics.RecordObservation(p.Name, string(p.Role), string(p.Method), string(target.Scenario), string(observation.Decision), string(observation.Reason))
			if observation.Decision == profiles.DecisionHarnessError {
				errText := "profile returned an error outcome"
				if lastErr != nil {
					errText = lastErr.Error()
				}
				return profiles.Result{
					Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
					Decision: observation.Decision, Reason: observation.Reason,
					ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, ExpectationMet: false,
					CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
					DecisionAt: now, DecisionLatency: now.Sub(revokedAt), Attempts: attempts,
					Evidence: observation.Evidence, Err: errText,
				}
			}
			if expectation.After == profiles.DecisionReject && observation.Decision == profiles.DecisionAccept {
				metrics.SoftfailTotal.WithLabelValues(p.Name, string(p.Method), stapling).Inc()
			}
			return profiles.Result{
				Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
				Decision: observation.Decision, Reason: observation.Reason,
				ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, ExpectationMet: false,
				CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
				DecisionAt: now, DecisionLatency: now.Sub(revokedAt), Attempts: attempts,
				Evidence: observation.Evidence,
			}
		}

		select {
		case <-ctx.Done():
			return profiles.Result{
				Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
				Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure,
				ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, ExpectationMet: false,
				CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
				Attempts: attempts, Evidence: lastObservation.Evidence, Err: ctx.Err().Error(),
			}
		case <-time.After(r.Config.PollInterval):
		}
	}
}
