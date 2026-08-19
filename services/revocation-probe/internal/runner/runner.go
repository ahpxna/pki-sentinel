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
}

// CycleReport is the structured JSON summary of one cycle (used by
// `probe run --once --output json` and the integration test).
type CycleReport struct {
	CycleID   string            `json:"cycle_id"`
	RevokedAt time.Time         `json:"revoked_at"`
	Results   []profiles.Result `json:"results"`
	Error     string            `json:"error,omitempty"`
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
	metrics.CertNotAfter.WithLabelValues(hostname, cert.SerialNumber, "canary").Set(float64(cert.Cert.NotAfter.Unix()))

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
	srv, err := canary.Start(hostname, tlsChainPEM, []byte(cert.KeyPEM), staple)
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("runner: starting canary server: %w", err)
	}
	defer srv.Close()

	target := profiles.Target{
		Host:       hostname,
		Port:       srv.Port,
		CAChainPEM: cert.ChainPEM,
		IssuerPEM:  cert.IssuerPEM,
		OCSPURL:    r.OCSPURL,
		CRLURL:     r.CRLURL,
	}

	// Pre-flight: every enabled profile must succeed (connection accepted,
	// outcome != rejected) BEFORE revocation. If a profile is already
	// "rejecting" here, the harness is broken — do not record a security
	// metric off of it. This is not optional; skipping it produces false
	// "detections" caused by unrelated connectivity failures.
	log.Printf("[cycle %s] pre-flight: verifying all profiles can reach the canary", cycleID)
	if err := r.preflight(ctx, target); err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return &CycleReport{CycleID: cycleID, Error: err.Error()}, err
	}

	tReq, tResp, err := r.Issuer.Revoke(ctx, cert.SerialNumber)
	_ = tReq
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("runner: revoking canary: %w", err)
	}
	revokedAt := tResp
	log.Printf("[cycle %s] revoked serial=%s at %s", cycleID, cert.SerialNumber, revokedAt.Format(time.RFC3339))

	if r.Stapling == canary.StaplingOn {
		if err := r.refreshRevokedStaple(ctx, srv, cert); err != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return nil, err
		}
	}

	results := r.pollAll(ctx, target, revokedAt)
	for _, result := range results {
		if result.Outcome == profiles.OutcomeError {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			report := &CycleReport{CycleID: cycleID, RevokedAt: revokedAt, Results: results}
			return report, fmt.Errorf("runner: profile %s failed: %s", result.Profile, result.Err)
		}
	}

	metrics.LastCycleTimestamp.Set(float64(time.Now().Unix()))
	metrics.CycleTotal.WithLabelValues("ok").Inc()

	return &CycleReport{CycleID: cycleID, RevokedAt: revokedAt, Results: results}, nil
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

// preflight runs every enabled profile once, before revocation, and
// requires OutcomeAccepted (i.e. the connection succeeds and is not
// rejected) from each.
func (r *Runner) preflight(ctx context.Context, target profiles.Target) error {
	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, r.Config.TimeoutFor(p.Name))
		outcome, err := p.Probe(pctx, target)
		cancel()
		if err != nil {
			return fmt.Errorf("preflight: profile %s errored: %w", p.Name, err)
		}
		if outcome == profiles.OutcomeRejected {
			return fmt.Errorf("preflight: profile %s rejected a pre-revocation certificate — harness is broken", p.Name)
		}
	}
	return nil
}

// pollAll polls every enabled profile in parallel every PollInterval until
// it reports OutcomeRejected or MaxWait elapses.
func (r *Runner) pollAll(ctx context.Context, target profiles.Target, revokedAt time.Time) []profiles.Result {
	var wg sync.WaitGroup
	results := make([]profiles.Result, 0, len(r.Profiles))
	var mu sync.Mutex

	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) {
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

	for {
		attempts++
		probeCtx, cancel := context.WithTimeout(ctx, r.Config.TimeoutFor(p.Name))
		outcome, err := p.Probe(probeCtx, target)
		cancel()
		if err != nil {
			outcome = profiles.OutcomeError
		}
		now := time.Now()

		switch outcome {
		case profiles.OutcomeRejected:
			dur := now.Sub(revokedAt)
			metrics.DetectionSeconds.WithLabelValues(p.Name, string(p.Method), stapling).Observe(dur.Seconds())
			metrics.DetectedTotal.WithLabelValues(p.Name, string(p.Method), stapling).Inc()
			return profiles.Result{
				Profile: p.Name, Method: p.Method, Outcome: profiles.OutcomeRejected,
				RevokedAt: revokedAt, DetectedAt: now, DetectionDur: dur, Attempts: attempts,
			}
		case profiles.OutcomeError:
			lastErr = err
			log.Printf("poll: profile %s error (attempt %d): %v", p.Name, attempts, err)
		}

		if time.Now().After(deadline) || (r.Config.MaxAttempts > 0 && attempts >= r.Config.MaxAttempts) {
			if outcome == profiles.OutcomeError {
				errText := "profile returned an error outcome"
				if lastErr != nil {
					errText = lastErr.Error()
				}
				return profiles.Result{
					Profile: p.Name, Method: p.Method, Outcome: profiles.OutcomeError,
					RevokedAt: revokedAt, Attempts: attempts, Err: errText,
				}
			}
			// Timeout without rejection: soft-fail. Recorded separately
			// from the detection histogram (which would otherwise be
			// polluted by an artificial +Inf-style bucket).
			metrics.SoftfailTotal.WithLabelValues(p.Name, string(p.Method), stapling).Inc()
			return profiles.Result{
				Profile: p.Name, Method: p.Method, Outcome: profiles.OutcomeAccepted,
				RevokedAt: revokedAt, Attempts: attempts,
			}
		}

		select {
		case <-ctx.Done():
			return profiles.Result{
				Profile: p.Name, Method: p.Method, Outcome: profiles.OutcomeError,
				RevokedAt: revokedAt, Attempts: attempts, Err: ctx.Err().Error(),
			}
		case <-time.After(r.Config.PollInterval):
		}
	}
}
