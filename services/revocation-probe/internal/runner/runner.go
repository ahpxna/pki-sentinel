// Package runner implements the revocation-probe cycle: issue a canary
// cert, start an ephemeral TLS server, run a pre-flight guard, revoke,
// poll every enabled profile in parallel until it detects rejection or
// times out, then tear down and emit metrics.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/canary"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/issuer"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/metrics"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/scenarios"
)

// Runner ties together the issuer, canary server, and profile registry.
type Runner struct {
	Issuer    *issuer.Client
	Config    *config.Config
	Profiles  []profiles.Profile
	Scenarios *scenarios.Registry
	Scenario  profiles.Scenario

	OCSPURL string
	CRLURL  string
	Domain  string // e.g. "internal" — canary hostnames are <uuid>.canary.<Domain>
	// CanaryBindHost and CanaryConnectHost are set only when profiles execute
	// in separate containers. The zero values preserve loopback-only local
	// canaries and direct in-process profile execution.
	CanaryBindHost    string
	CanaryConnectHost string
	// EvidenceDir holds raw command and status artifacts referenced by the
	// signed report. It must be durable and access-controlled in deployment.
	EvidenceDir string
}

// CycleReport is the structured JSON summary of one cycle (used by
// `probe run --once --output json` and the integration test).
type CycleReport struct {
	CycleID        string                     `json:"cycle_id"`
	Scenario       profiles.Scenario          `json:"scenario"`
	ScenarioDigest string                     `json:"scenario_digest"`
	ConfigDigest   string                     `json:"config_digest"`
	Valid          bool                       `json:"valid"`
	Phase          CyclePhase                 `json:"phase"`
	RevokeAckAt    time.Time                  `json:"revoke_ack_at"`
	Timeline       Timeline                   `json:"timeline"`
	Artifacts      []profiles.Artifact        `json:"artifacts,omitempty"`
	Preflight      []profiles.PreflightResult `json:"preflight,omitempty"`
	Results        []profiles.Result          `json:"results"`
	Error          string                     `json:"error,omitempty"`
}

// CyclePhase records the last experiment boundary reached by a cycle. Failed
// cycles retain this value in their signed report so invalid trials remain in
// the denominator instead of disappearing from the evidence set.
type CyclePhase string

const (
	PhaseIssue           CyclePhase = "issue"
	PhaseCanary          CyclePhase = "canary"
	PhasePreflight       CyclePhase = "preflight"
	PhaseRevoke          CyclePhase = "revoke"
	PhaseObserve         CyclePhase = "observe"
	PhasePersistEvidence CyclePhase = "persist_evidence"
	PhaseEvaluate        CyclePhase = "evaluate"
	PhaseComplete        CyclePhase = "complete"
)

// CanonicalJSON returns the single JSON representation used for both machine
// output and assurance attestation payloads. It intentionally uses compact
// encoding/json output with no trailing newline so callers can preserve these
// exact bytes across stdout capture, hashing, signing, and verification.
func (r *CycleReport) CanonicalJSON() ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("runner: cannot serialize a nil cycle report")
	}
	contents, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("runner: marshal cycle report: %w", err)
	}
	return contents, nil
}

// Timeline preserves measurement boundaries instead of overloading one
// end-to-end latency with OCSP propagation, CRL publication, and client work.
type Timeline struct {
	RevokeRequestAt           time.Time     `json:"revoke_request_at,omitempty"`
	RevokeAckAt               time.Time     `json:"revoke_ack_at,omitempty"`
	OCSPFirstRevoked          time.Time     `json:"ocsp_first_revoked_at,omitempty"`
	CRLFirstRevoked           time.Time     `json:"crl_first_revoked_at,omitempty"`
	StaplePublished           time.Time     `json:"staple_published_at,omitempty"`
	OCSPPropagationLatency    time.Duration `json:"ocsp_propagation_latency_ns,omitempty"`
	CRLPropagationLatency     time.Duration `json:"crl_propagation_latency_ns,omitempty"`
	StapleDistributionLatency time.Duration `json:"staple_distribution_latency_ns,omitempty"`
}

// RunOnce executes exactly one probe cycle.
func (r *Runner) RunOnce(ctx context.Context) (*CycleReport, error) {
	if r.Config == nil {
		return nil, fmt.Errorf("runner: config is required")
	}
	if len(r.Config.EnabledNames()) == 0 {
		return nil, fmt.Errorf("runner: at least one profile must be enabled")
	}
	configDigest, err := r.Config.Digest()
	if err != nil {
		return nil, fmt.Errorf("runner: digest config: %w", err)
	}
	scenario := r.Scenario
	if scenario == "" {
		return nil, fmt.Errorf("runner: scenario is required")
	}
	manifest, ok := r.Scenarios.Manifest(scenario)
	if !ok {
		return nil, fmt.Errorf("runner: no loaded scenario manifest for %s", scenario)
	}
	switch manifest.Stapling {
	case scenarios.StaplingOn, scenarios.StaplingOff, scenarios.StaplingStale:
	default:
		return nil, fmt.Errorf("runner: scenario %s has invalid stapling mode %q", scenario, manifest.Stapling)
	}

	stapling := canary.StaplingMode(manifest.Stapling)
	cycleID := uuid.NewString()
	hostname := fmt.Sprintf("canary-%s.canary.%s", cycleID, r.Domain)
	report := &CycleReport{
		CycleID: cycleID, Scenario: scenario, ScenarioDigest: manifest.Digest, ConfigDigest: configDigest,
		Phase: PhaseIssue, Results: []profiles.Result{},
	}
	fail := func(phase CyclePhase, err error) (*CycleReport, error) {
		report.Phase = phase
		report.Error = err.Error()
		return report, err
	}

	log.Printf("[cycle %s] issuing canary cert for %s", cycleID, hostname)
	cert, err := r.Issuer.IssueCanary(ctx, hostname)
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhaseIssue, fmt.Errorf("runner: issuing canary: %w", err))
	}
	metrics.CertNotAfter.Set(float64(cert.Cert.NotAfter.Unix()))

	report.Phase = PhasePersistEvidence
	report.Artifacts, err = r.persistCycleArtifacts(cycleID, map[string]cycleArtifact{
		"leaf.pem":  {MediaType: "application/x-pem-file", Contents: []byte(cert.CertPEM)},
		"chain.pem": {MediaType: "application/x-pem-file", Contents: []byte(cert.ChainPEM)},
	})
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhasePersistEvidence, fmt.Errorf("runner: persisting cycle artifacts: %w", err))
	}

	var staple []byte
	if stapling == canary.StaplingOn || stapling == canary.StaplingStale {
		// StaplingStale fetches the OCSP response BEFORE revocation and
		// keeps serving that same stale "good" response after revocation —
		// exactly how an attacker would extend a compromised cert's
		// perceived validity.
		var status int
		staple, status, err = r.Issuer.FetchOCSPResponse(ctx, r.OCSPURL, cert.Cert, cert.IssuerCert)
		if err != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhaseCanary, fmt.Errorf("runner: fetching pre-revocation OCSP staple: %w", err))
		}
		if status != ocsp.Good {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhaseCanary, fmt.Errorf("runner: pre-revocation OCSP status=%d, expected good", status))
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
	report.Phase = PhaseCanary
	srv, err := canary.StartOn(bindHost, hostname, tlsChainPEM, []byte(cert.KeyPEM), staple)
	if err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhaseCanary, fmt.Errorf("runner: starting canary server: %w", err))
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
		OCSPFreshness: profiles.OCSPFreshnessPolicy{
			MaxClockSkew:            r.Config.OCSPFreshness.MaxClockSkew,
			RequireNextUpdate:       r.Config.OCSPFreshness.RequireNextUpdate,
			MaxAgeWithoutNextUpdate: r.Config.OCSPFreshness.MaxAgeWithoutNextUpdate,
		},
	}

	// Pre-flight validates each scenario-specific BEFORE contract and retains
	// the exact observation as signed evidence. A strict stapling client may
	// legitimately reject a missing status before revocation.
	report.Phase = PhasePreflight
	log.Printf("[cycle %s] pre-flight: verifying all profiles can reach the canary", cycleID)
	preflight, preflightErr := r.preflight(ctx, target)
	report.Preflight = preflight
	if preflightErr != nil {
		if err := r.persistPreflightEvidence(cycleID, report.Preflight); err != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhasePersistEvidence, fmt.Errorf("runner: preflight failed (%v); persisting preflight evidence: %w", preflightErr, err))
		}
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhasePreflight, preflightErr)
	}

	// Do not put evidence I/O between a successful preflight and the revoke
	// request. The BEFORE observation is retained in memory and persisted after
	// post-revocation measurement so the causal guard remains temporally tight.
	report.Phase = PhaseRevoke
	tReq, tResp, err := r.Issuer.Revoke(ctx, cert.SerialNumber)
	if err != nil {
		if persistErr := r.persistPreflightEvidence(cycleID, report.Preflight); persistErr != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhasePersistEvidence, fmt.Errorf("runner: revoking canary: %v; persisting preflight evidence: %w", err, persistErr))
		}
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhaseRevoke, fmt.Errorf("runner: revoking canary: %w", err))
	}
	revokeAckAt := tResp
	report.RevokeAckAt = revokeAckAt
	log.Printf("[cycle %s] revoked serial=%s at %s", cycleID, cert.SerialNumber, revokeAckAt.Format(time.RFC3339))
	timeline := Timeline{RevokeRequestAt: tReq, RevokeAckAt: revokeAckAt}

	// Status channels begin immediately after the issuer acknowledgement. They
	// never form a global barrier for clients using a different delivery path.
	report.Phase = PhaseObserve
	issuerAckReady := closedEvidence()
	ocspPublishedReady := make(chan struct{})
	crlPublishedReady := make(chan struct{})
	ocspDone := make(chan []profiles.Result, 1)
	crlDone := make(chan []profiles.Result, 1)
	var ocspPublishedErr error
	var crlPublishedErr error
	go func() {
		results := r.pollMethod(ctx, profiles.MethodOCSPDirect, target, revokeAckAt)
		ocspPublishedErr = publicationError(profiles.MethodOCSPDirect, results)
		ocspDone <- results
		close(ocspPublishedReady)
	}()
	go func() {
		results := r.pollMethod(ctx, profiles.MethodCRL, target, revokeAckAt)
		crlPublishedErr = publicationError(profiles.MethodCRL, results)
		crlDone <- results
		close(crlPublishedReady)
	}()

	stapleReady := make(chan struct{})
	var stapleErr error
	if stapling == canary.StaplingOn {
		go func() {
			timeline.OCSPFirstRevoked, stapleErr = r.refreshRevokedStaple(ctx, srv, cert)
			if stapleErr == nil {
				timeline.StaplePublished = time.Now().UTC()
			}
			close(stapleReady)
		}()
	} else {
		close(stapleReady)
	}

	barriers := map[scenarios.EvidenceDependency]evidenceBarrier{
		scenarios.EvidenceIssuerAck:       {ready: issuerAckReady},
		scenarios.EvidenceOCSPPublished:   {ready: ocspPublishedReady, err: func() error { return ocspPublishedErr }},
		scenarios.EvidenceCRLPublished:    {ready: crlPublishedReady, err: func() error { return crlPublishedErr }},
		scenarios.EvidenceStaplePublished: {ready: stapleReady, err: func() error { return stapleErr }},
	}
	clients := r.pollClients(ctx, target, revokeAckAt, barriers)
	oracles := append(<-ocspDone, <-crlDone...)
	// Reporting waits for the staple publisher to finish. The manifest decides
	// which client profiles wait on this boundary; this wait establishes a
	// happens-before edge for timeline data in every selected scenario.
	if stapling == canary.StaplingOn {
		<-stapleReady
	}
	for _, result := range oracles {
		if result.Method == profiles.MethodOCSPDirect && result.Decision == profiles.DecisionReject && result.Reason == profiles.ReasonRevoked {
			timeline.OCSPFirstRevoked = earliest(timeline.OCSPFirstRevoked, result.DecisionAt)
		}
		if result.Method == profiles.MethodCRL && result.Decision == profiles.DecisionReject && result.Reason == profiles.ReasonRevoked {
			timeline.CRLFirstRevoked = earliest(timeline.CRLFirstRevoked, result.DecisionAt)
		}
	}

	results := append(oracles, clients...)
	sortResults(results)
	timeline.derive()
	for i := range results {
		if r.dependsOn(results[i].Scenario, results[i].Profile, scenarios.EvidenceStaplePublished) && !timeline.StaplePublished.IsZero() && !results[i].DecisionAt.IsZero() {
			results[i].EnforcementLatency = results[i].DecisionAt.Sub(timeline.StaplePublished)
		}
	}
	report.Timeline = timeline
	report.Results = results

	report.Phase = PhasePersistEvidence
	if err := r.persistPreflightEvidence(cycleID, report.Preflight); err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhasePersistEvidence, fmt.Errorf("runner: persisting preflight evidence: %w", err))
	}
	if err := r.persistEvidence(cycleID, report.Results); err != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhasePersistEvidence, fmt.Errorf("runner: persisting post-revocation evidence: %w", err))
	}
	if stapleErr != nil {
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhaseObserve, fmt.Errorf("runner: publishing revoked OCSP staple: %w", stapleErr))
	}

	report.Phase = PhaseEvaluate
	for _, result := range report.Results {
		if result.Decision == profiles.DecisionHarnessError || result.Err != "" {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhaseEvaluate, fmt.Errorf("runner: profile %s failed: %s", result.Profile, result.Err))
		}
	}
	// A cycle is valid once all required observations and evidence were
	// collected without a harness error. A regression or policy violation is a
	// valid security finding, not an invalid trial.
	report.Valid = true
	for _, result := range report.Results {
		if !result.ExpectationMet {
			metrics.CycleTotal.WithLabelValues("regression").Inc()
			return fail(PhaseEvaluate, fmt.Errorf("runner: security regression: profile %s produced %s/%s; expected %s", result.Profile, result.Decision, result.Reason, result.ExpectedDecision))
		}
		if !result.PolicyMet {
			metrics.PolicyViolations.WithLabelValues(result.Profile, string(result.Method), string(result.Scenario), string(result.Decision), string(result.Reason)).Inc()
			if r.Config.Policy.Enforce {
				metrics.CycleTotal.WithLabelValues("policy_violation").Inc()
				return fail(PhaseEvaluate, fmt.Errorf("runner: security policy violation: profile %s produced %s/%s; required %s", result.Profile, result.Decision, result.Reason, result.PolicyDecision))
			}
		}
	}

	metrics.LastCycleTimestamp.Set(float64(time.Now().Unix()))
	metrics.CycleTotal.WithLabelValues("ok").Inc()
	report.Phase = PhaseComplete
	return report, nil
}

func publicationError(method profiles.CheckMethod, results []profiles.Result) error {
	if len(results) == 0 {
		return fmt.Errorf("no enabled %s status oracle produced publication evidence", method)
	}
	published := false
	for _, result := range results {
		if result.Decision == profiles.DecisionHarnessError || result.Err != "" {
			if result.Err != "" {
				return fmt.Errorf("status oracle %s failed while establishing %s publication: %s", result.Profile, method, result.Err)
			}
			return fmt.Errorf("status oracle %s failed while establishing %s publication", result.Profile, method)
		}
		if result.ExpectationMet && result.Decision == profiles.DecisionReject && result.Reason == profiles.ReasonRevoked {
			published = true
		}
	}
	if !published {
		return fmt.Errorf("%s publication was not established as REJECT/REVOKED", method)
	}
	return nil
}

func sortResults(results []profiles.Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Profile != results[j].Profile {
			return results[i].Profile < results[j].Profile
		}
		if results[i].Role != results[j].Role {
			return results[i].Role < results[j].Role
		}
		return results[i].Method < results[j].Method
	})
}

func (t *Timeline) derive() {
	if !t.RevokeAckAt.IsZero() {
		if !t.OCSPFirstRevoked.IsZero() {
			t.OCSPPropagationLatency = t.OCSPFirstRevoked.Sub(t.RevokeAckAt)
		}
		if !t.CRLFirstRevoked.IsZero() {
			t.CRLPropagationLatency = t.CRLFirstRevoked.Sub(t.RevokeAckAt)
		}
		if !t.StaplePublished.IsZero() {
			t.StapleDistributionLatency = t.StaplePublished.Sub(t.RevokeAckAt)
		}
	}
}

func (r *Runner) refreshRevokedStaple(ctx context.Context, srv *canary.Server, cert *issuer.CanaryCert) (time.Time, error) {
	deadline := time.Now().Add(r.Config.MaxWait)
	var lastErr error
	var lastStatus int
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return time.Time{}, fmt.Errorf("runner: waiting for revoked OCSP staple: %w", lastErr)
			}
			return time.Time{}, fmt.Errorf("runner: waiting for revoked OCSP staple: last status=%d", lastStatus)
		}
		attemptTimeout := 5 * time.Second
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		staple, status, err := r.Issuer.FetchOCSPResponse(attemptCtx, r.OCSPURL, cert.Cert, cert.IssuerCert)
		cancel()
		lastErr, lastStatus = err, status
		if err == nil && status == ocsp.Revoked {
			srv.SetOCSPStaple(staple)
			return time.Now().UTC(), nil
		}

		sleepFor := r.Config.PollInterval
		if remaining := time.Until(deadline); remaining < sleepFor {
			sleepFor = remaining
		}
		if sleepFor <= 0 {
			continue
		}
		timer := time.NewTimer(sleepFor)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return time.Time{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func earliest(current, candidate time.Time) time.Time {
	if current.IsZero() || (!candidate.IsZero() && candidate.Before(current)) {
		return candidate
	}
	return current
}

// preflight runs every enabled profile once before revocation and validates
// its scenario-specific contract. A strict stapling client is expected to
// reject a missing staple even when the certificate itself is still good.
func (r *Runner) preflight(ctx context.Context, target profiles.Target) ([]profiles.PreflightResult, error) {
	results := make([]profiles.PreflightResult, 0, len(r.Profiles))
	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) {
			continue
		}
		contract, ok := r.Scenarios.Contract(target.Scenario, p.Name)
		if !ok {
			return results, fmt.Errorf("preflight: profile %s has no expectation for scenario %s", p.Name, target.Scenario)
		}
		expectation := contract.Baseline
		pctx, cancel := context.WithTimeout(ctx, r.Config.TimeoutFor(p.Name))
		observation, err := p.Probe(pctx, target)
		cancel()
		observedAt := time.Now().UTC()
		if err != nil {
			observation.Decision = profiles.DecisionHarnessError
			observation.Reason = profiles.ReasonHarnessFailure
		}
		result := profiles.PreflightResult{
			Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
			Decision: observation.Decision, Reason: observation.Reason,
			ExpectedDecision: expectation.Before, ExpectedReasons: expectation.BeforeReasons,
			ExpectationMet: expectation.MatchesBefore(observation), ObservedAt: observedAt, Evidence: observation.Evidence,
		}
		if err != nil {
			result.Err = err.Error()
		}
		results = append(results, result)
		if err != nil {
			return results, fmt.Errorf("preflight: profile %s errored: %w", p.Name, err)
		}
		if !result.ExpectationMet {
			return results, fmt.Errorf("preflight: profile %s produced %s/%s, expected %s/%v for scenario %s", p.Name, observation.Decision, observation.Reason, expectation.Before, expectation.BeforeReasons, target.Scenario)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Profile < results[j].Profile })
	return results, nil
}

// pollClients waits only on the manifest-declared evidence boundaries for a
// profile. The implementation method does not imply a wait condition.
func (r *Runner) pollClients(ctx context.Context, target profiles.Target, revokedAt time.Time, barriers map[scenarios.EvidenceDependency]evidenceBarrier) []profiles.Result {
	var wg sync.WaitGroup
	results := make([]profiles.Result, 0, len(r.Profiles))
	var mu sync.Mutex
	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) || p.Role != profiles.RoleClientExecutor {
			continue
		}
		wg.Add(1)
		go func(p profiles.Profile) {
			defer wg.Done()
			if err := r.waitForEvidence(ctx, target.Scenario, p.Name, barriers); err != nil {
				mu.Lock()
				results = append(results, r.harnessResult(p, target, revokedAt, err))
				mu.Unlock()
				return
			}
			result := r.pollOne(ctx, p, target, revokedAt)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return results
}

type evidenceBarrier struct {
	ready <-chan struct{}
	err   func() error
}

func closedEvidence() <-chan struct{} {
	ready := make(chan struct{})
	close(ready)
	return ready
}

func (r *Runner) waitForEvidence(ctx context.Context, scenario profiles.Scenario, profile string, barriers map[scenarios.EvidenceDependency]evidenceBarrier) error {
	dependencies, ok := r.Scenarios.Dependencies(scenario, profile)
	if !ok {
		return fmt.Errorf("profile %s has no evidence dependencies for scenario %s", profile, scenario)
	}
	for _, dependency := range dependencies {
		barrier, ok := barriers[dependency]
		if !ok || barrier.ready == nil {
			return fmt.Errorf("profile %s requires unavailable evidence dependency %s", profile, dependency)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-barrier.ready:
		}
		if barrier.err != nil {
			if err := barrier.err(); err != nil {
				return fmt.Errorf("profile %s waiting for %s: %w", profile, dependency, err)
			}
		}
	}
	return nil
}

func (r *Runner) dependsOn(scenario profiles.Scenario, profile string, dependency scenarios.EvidenceDependency) bool {
	dependencies, ok := r.Scenarios.Dependencies(scenario, profile)
	if !ok {
		return false
	}
	for _, candidate := range dependencies {
		if candidate == dependency {
			return true
		}
	}
	return false
}

func (r *Runner) harnessResult(p profiles.Profile, target profiles.Target, revokedAt time.Time, err error) profiles.Result {
	contract, _ := r.Scenarios.Contract(target.Scenario, p.Name)
	expectation := contract.Baseline
	return profiles.Result{Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario, Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure, ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt, Err: err.Error()}
}

func (r *Runner) pollMethod(ctx context.Context, method profiles.CheckMethod, target profiles.Target, revokedAt time.Time) []profiles.Result {
	var wg sync.WaitGroup
	results := make([]profiles.Result, 0, len(r.Profiles))
	var mu sync.Mutex

	for _, p := range r.Profiles {
		if !r.Config.IsEnabled(p.Name) || p.Role != profiles.RoleStatusOracle || p.Method != method {
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

func (r *Runner) pollOne(ctx context.Context, p profiles.Profile, target profiles.Target, revokedAt time.Time) (result profiles.Result) {
	var firstAttempt time.Time
	defer func() {
		if !firstAttempt.IsZero() {
			result.ClientAttemptAt = firstAttempt
		}
		result = r.applyPolicy(p, target.Scenario, result)
	}()
	deadline := time.Now().Add(r.Config.MaxWait)
	attempts := 0
	stapling := string(r.staplingFor(target.Scenario))
	var lastErr error
	lastObservation := profiles.Observation{Decision: profiles.DecisionInconclusive, Reason: profiles.ReasonHarnessFailure}
	contract, ok := r.Scenarios.Contract(target.Scenario, p.Name)
	if !ok {
		return profiles.Result{
			Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
			Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure,
			CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
			Err: fmt.Sprintf("profile has no expectation for scenario %s", target.Scenario),
		}
	}
	expectation := contract.Baseline

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return r.exhaustedResult(p, target, revokedAt, expectation, lastObservation, lastErr, attempts, time.Now(), stapling)
		}
		attempts++
		if firstAttempt.IsZero() {
			firstAttempt = time.Now().UTC()
		}
		attemptTimeout := r.Config.TimeoutFor(p.Name)
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}
		probeCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
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
			return r.exhaustedResult(p, target, revokedAt, expectation, observation, lastErr, attempts, now, stapling)
		}

		wait := r.Config.PollInterval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return profiles.Result{
				Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
				Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure,
				ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, ExpectationMet: false,
				CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
				Attempts: attempts, Evidence: lastObservation.Evidence, Err: ctx.Err().Error(),
			}
		case <-timer.C:
		}
	}
}

func (r *Runner) exhaustedResult(p profiles.Profile, target profiles.Target, revokedAt time.Time, expectation profiles.Expectation, observation profiles.Observation, lastErr error, attempts int, now time.Time, stapling string) profiles.Result {
	metrics.RecordObservation(p.Name, string(p.Role), string(p.Method), string(target.Scenario), string(observation.Decision), string(observation.Reason))
	result := profiles.Result{
		Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
		Decision: observation.Decision, Reason: observation.Reason,
		ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons, ExpectationMet: false,
		CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt,
		DecisionAt: now, DecisionLatency: now.Sub(revokedAt), Attempts: attempts,
		Evidence: observation.Evidence,
	}
	if observation.Decision == profiles.DecisionHarnessError {
		result.Err = "profile returned an error outcome"
		if lastErr != nil {
			result.Err = lastErr.Error()
		}
		return result
	}
	if expectation.After == profiles.DecisionReject && observation.Decision == profiles.DecisionAccept {
		metrics.SoftfailTotal.WithLabelValues(p.Name, string(p.Method), stapling).Inc()
	}
	return result
}

func (r *Runner) staplingFor(scenario profiles.Scenario) scenarios.StaplingMode {
	manifest, ok := r.Scenarios.Manifest(scenario)
	if !ok {
		return ""
	}
	return manifest.Stapling
}

func (r *Runner) applyPolicy(profile profiles.Profile, scenario profiles.Scenario, result profiles.Result) profiles.Result {
	contract, ok := r.Scenarios.Contract(scenario, profile.Name)
	if !ok {
		result.PolicyMet = false
		return result
	}
	policy := contract.Policy
	result.PolicyDecision = policy.After
	result.PolicyReasons = policy.AfterReasons
	result.PolicyMet = policy.MatchesAfter(profiles.Observation{Decision: result.Decision, Reason: result.Reason})
	return result
}
