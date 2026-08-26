// Package runner implements the revocation-probe cycle: issue a canary
// cert, start an ephemeral TLS server, run a pre-flight guard, revoke,
// poll every enabled profile in parallel until it detects rejection or
// times out, then tear down and emit metrics.
package runner

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
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
	Issuer    CanaryIssuer
	Config    *config.Config
	Profiles  []profiles.Profile
	Scenarios *scenarios.Registry
	Scenario  profiles.Scenario

	OCSPURL string
	CRLURL  string
	Domain  string // e.g. "internal" — canary hostnames are <uuid>.canary.<Domain>
	// IssuerEndpoint is a non-secret Vault address retained in the signed run
	// configuration; credentials are never included in evidence.
	IssuerEndpoint string
	// CanaryBindHost and CanaryConnectHost are set only when profiles execute
	// in separate containers. The zero values preserve loopback-only local
	// canaries and direct in-process profile execution.
	CanaryBindHost    string
	CanaryConnectHost string
	// EvidenceDir holds raw command and status artifacts referenced by the
	// signed report. It must be durable and access-controlled in deployment.
	EvidenceDir string
	// ExecutorURLs records the configured profile-to-executor mapping so the
	// signed run configuration can reproduce where each implementation ran.
	ExecutorURLs map[string]string
}

// CanaryIssuer covers the issuer operations performed by a single cycle.
// It permits cleanup behavior to be verified without a live Vault instance.
type CanaryIssuer interface {
	IssueCanary(context.Context, string) (*issuer.CanaryCert, error)
	RevokeAt(context.Context, string, time.Time) (time.Time, time.Time, error)
	Revoke(context.Context, string) (time.Time, time.Time, error)
	FetchOCSPResponse(context.Context, string, *x509.Certificate, *x509.Certificate) ([]byte, int, error)
}

// CycleReport is the structured JSON summary of one cycle (used by
// `probe run --once --output json` and the integration test).
type CycleReport struct {
	CycleID          string                     `json:"cycle_id"`
	Scenario         profiles.Scenario          `json:"scenario"`
	ScenarioDigest   string                     `json:"scenario_digest"`
	RunConfig        RunConfigSnapshot          `json:"run_config"`
	RunConfigDigest  string                     `json:"run_config_digest"`
	IssuedLeafSHA256 string                     `json:"issued_leaf_sha256"`
	Valid            bool                       `json:"valid"`
	Phase            CyclePhase                 `json:"phase"`
	RevokeAckAt      time.Time                  `json:"revoke_ack_at"`
	Cleanup          CleanupStatus              `json:"cleanup"`
	Timeline         Timeline                   `json:"timeline"`
	Artifacts        []profiles.Artifact        `json:"artifacts,omitempty"`
	Preflight        []profiles.PreflightResult `json:"preflight,omitempty"`
	Results          []profiles.Result          `json:"results"`
	Error            string                     `json:"error,omitempty"`
}

// CleanupStatus records a compensating revocation performed after a cycle
// fails after certificate issuance but before the experiment revoke succeeds.
// It is distinct from RevokeAckAt, which belongs only to the measurement.
type CleanupStatus struct {
	Attempted bool   `json:"attempted"`
	Revoked   bool   `json:"revoked"`
	Error     string `json:"error,omitempty"`
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
	RevokeRequestAt                time.Time     `json:"revoke_request_at,omitempty"`
	RevokeAckAt                    time.Time     `json:"revoke_ack_at,omitempty"`
	OCSPOracleFirstRevokedAt       time.Time     `json:"ocsp_oracle_first_revoked_at,omitempty"`
	CRLOracleFirstRevokedAt        time.Time     `json:"crl_oracle_first_revoked_at,omitempty"`
	StapleSourceFirstRevokedAt     time.Time     `json:"staple_source_first_revoked_at,omitempty"`
	StaplePublishedAt              time.Time     `json:"staple_published_at,omitempty"`
	OCSPOraclePropagationLatency   time.Duration `json:"ocsp_oracle_propagation_latency_ns,omitempty"`
	CRLOraclePropagationLatency    time.Duration `json:"crl_oracle_propagation_latency_ns,omitempty"`
	StapleSourcePropagationLatency time.Duration `json:"staple_source_propagation_latency_ns,omitempty"`
	StapleDistributionLatency      time.Duration `json:"staple_distribution_latency_ns,omitempty"`

	revokeRequestMono            time.Time
	revokeAckMono                time.Time
	ocspOracleFirstRevokedMono   time.Time
	crlOracleFirstRevokedMono    time.Time
	stapleSourceFirstRevokedMono time.Time
	staplePublishedMono          time.Time
}

// RunOnce executes exactly one probe cycle.
func (r *Runner) RunOnce(ctx context.Context) (*CycleReport, error) {
	if r.Config == nil {
		return nil, fmt.Errorf("runner: config is required")
	}
	if len(r.Config.EnabledNames()) == 0 {
		return nil, fmt.Errorf("runner: at least one profile must be enabled")
	}
	if err := r.validateEnabledRoles(); err != nil {
		return nil, err
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
	runConfig := r.runConfigSnapshot()
	runConfigDigest, err := digestRunConfig(runConfig)
	if err != nil {
		return nil, fmt.Errorf("runner: digest run config: %w", err)
	}
	cycleID := uuid.NewString()
	hostname := fmt.Sprintf("canary-%s.canary.%s", cycleID, r.Domain)
	report := &CycleReport{
		CycleID: cycleID, Scenario: scenario, ScenarioDigest: manifest.Digest,
		RunConfig: runConfig, RunConfigDigest: runConfigDigest,
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
	cleanupArmed := true
	defer func() {
		if !cleanupArmed {
			return
		}
		report.Cleanup.Attempted = true
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, _, cleanupErr := r.Issuer.Revoke(cleanupCtx, cert.SerialNumber); cleanupErr != nil {
			report.Cleanup.Error = cleanupErr.Error()
			log.Printf("[cycle %s] compensating revoke for serial=%s failed: %v", cycleID, cert.SerialNumber, cleanupErr)
			return
		}
		report.Cleanup.Revoked = true
		log.Printf("[cycle %s] compensating revoke completed for serial=%s", cycleID, cert.SerialNumber)
	}()

	report.Phase = PhasePersistEvidence
	report.Artifacts, err = r.persistCycleArtifacts(cycleID, map[string]cycleArtifact{
		"leaf.pem":      {MediaType: "application/x-pem-file", Contents: []byte(cert.CertPEM)},
		"chain.pem":     {MediaType: "application/x-pem-file", Contents: []byte(cert.ChainPEM)},
		"scenario.json": {MediaType: "application/json", Contents: manifest.CanonicalJSON()},
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
		if err := r.validateOCSPStaple(staple, cert, ocsp.Good); err != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhaseCanary, fmt.Errorf("runner: invalid pre-revocation OCSP staple: %w", err))
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

	leafDigest := sha256.Sum256(cert.Cert.Raw)
	report.IssuedLeafSHA256 = hex.EncodeToString(leafDigest[:])
	target := profiles.Target{
		Host:              hostname,
		ConnectHost:       r.CanaryConnectHost,
		Port:              srv.Port,
		CAChainPEM:        cert.ChainPEM,
		IssuerPEM:         cert.IssuerPEM,
		OCSPURL:           r.OCSPURL,
		CRLURL:            r.CRLURL,
		CertificateSerial: cert.SerialNumber,
		IssuedLeafSHA256:  report.IssuedLeafSHA256,
		Scenario:          scenario,
		StatusFreshness: profiles.StatusFreshnessPolicy{
			MaxClockSkew: r.Config.StatusFreshness.MaxClockSkew,
		},
		OCSPFreshness: profiles.OCSPFreshnessPolicy{
			RequireNextUpdate:       r.Config.OCSPFreshness.RequireNextUpdate,
			MaxAgeWithoutNextUpdate: r.Config.OCSPFreshness.MaxAgeWithoutNextUpdate,
		},
		CRLFreshness: profiles.CRLFreshnessPolicy{
			RequireNextUpdate: r.Config.CRLFreshness.RequireNextUpdate,
			MaxAge:            r.Config.CRLFreshness.MaxAge,
		},
	}

	// Pre-flight validates each scenario-specific BEFORE contract and retains
	// the exact observation as signed evidence. A strict stapling client may
	// legitimately reject a missing status before revocation.
	report.Phase = PhasePreflight
	log.Printf("[cycle %s] pre-flight: verifying all profiles can reach the canary", cycleID)
	preflight, preflightObservedMono, preflightErr := r.preflight(ctx, target)
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
	// request. Enforce an explicit age bound immediately before the issuer side
	// effect so every signed BEFORE observation is causally adjacent to revoke.
	revokeRequestAt := time.Now()
	if err := validatePreflightAge(preflightObservedMono, revokeRequestAt, r.Config.PreflightMaxAge); err != nil {
		if persistErr := r.persistPreflightEvidence(cycleID, report.Preflight); persistErr != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhasePersistEvidence, fmt.Errorf("runner: stale preflight (%v); persisting preflight evidence: %w", err, persistErr))
		}
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhasePreflight, err)
	}
	report.Phase = PhaseRevoke
	tReq, tResp, err := r.Issuer.RevokeAt(ctx, cert.SerialNumber, revokeRequestAt)
	if err != nil {
		if persistErr := r.persistPreflightEvidence(cycleID, report.Preflight); persistErr != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhasePersistEvidence, fmt.Errorf("runner: revoking canary: %v; persisting preflight evidence: %w", err, persistErr))
		}
		metrics.CycleTotal.WithLabelValues("error").Inc()
		return fail(PhaseRevoke, fmt.Errorf("runner: revoking canary: %w", err))
	}
	cleanupArmed = false
	revokeAckAt := tResp
	report.RevokeAckAt = revokeAckAt.UTC()
	for i := range report.Preflight {
		if observedAt, ok := preflightObservedMono[report.Preflight[i].Profile]; ok {
			report.Preflight[i].AgeAtRevoke = tReq.Sub(observedAt)
		}
	}
	log.Printf("[cycle %s] revoked serial=%s at %s", cycleID, cert.SerialNumber, revokeAckAt.Format(time.RFC3339))
	timeline := newTimeline(tReq, revokeAckAt)

	// Status oracles start immediately after issuer acknowledgement. Publication
	// barriers are satisfied only by successful REJECT/REVOKED evidence; merely
	// finishing an oracle goroutine must never release a dependent client.
	report.Phase = PhaseObserve
	issuerAckBarrier := newEvidenceBarrier()
	issuerAckBarrier.satisfy(revokeAckAt)
	ocspBarrier := newEvidenceBarrier()
	crlBarrier := newEvidenceBarrier()
	stapleBarrier := newEvidenceBarrier()

	ocspDone := make(chan []profiles.Result, 1)
	crlDone := make(chan []profiles.Result, 1)
	go func() {
		results := r.pollMethod(ctx, profiles.MethodOCSPDirect, target, revokeAckAt)
		if at, err := publicationEvidence(profiles.MethodOCSPDirect, results); err != nil {
			ocspBarrier.fail(err)
		} else {
			ocspBarrier.satisfy(at)
		}
		ocspDone <- results
	}()
	go func() {
		results := r.pollMethod(ctx, profiles.MethodCRL, target, revokeAckAt)
		if at, err := publicationEvidence(profiles.MethodCRL, results); err != nil {
			crlBarrier.fail(err)
		} else {
			crlBarrier.satisfy(at)
		}
		crlDone <- results
	}()

	var stapleErr error
	var stapleSourceRevokedAt time.Time
	var publishedStaple []byte
	if stapling == canary.StaplingOn {
		go func() {
			staple, sourceRevokedAt, publishedAt, err := r.refreshRevokedStaple(ctx, srv, cert)
			stapleErr = err
			stapleSourceRevokedAt = sourceRevokedAt
			publishedStaple = staple
			if err != nil {
				stapleBarrier.fail(err)
				return
			}
			stapleBarrier.satisfy(publishedAt)
		}()
	} else {
		stapleBarrier.fail(fmt.Errorf("staple_published is unavailable when execution.stapling=%s", stapling))
	}

	barriers := map[scenarios.EvidenceDependency]*evidenceBarrier{
		scenarios.EvidenceIssuerAck:       issuerAckBarrier,
		scenarios.EvidenceOCSPPublished:   ocspBarrier,
		scenarios.EvidenceCRLPublished:    crlBarrier,
		scenarios.EvidenceStaplePublished: stapleBarrier,
	}
	clients := r.pollClients(ctx, target, revokeAckAt, barriers)
	oracles := append(<-ocspDone, <-crlDone...)
	if stapling == canary.StaplingOn {
		<-stapleBarrier.ready
	}
	if at, err := ocspBarrier.state(); err == nil {
		timeline.setOCSPOracleRevoked(at)
	}
	if at, err := crlBarrier.state(); err == nil {
		timeline.setCRLOracleRevoked(at)
	}
	if at, err := stapleBarrier.state(); err == nil {
		timeline.setStapleSourceRevoked(stapleSourceRevokedAt)
		timeline.setStaplePublished(at)
	}

	results := append(oracles, clients...)
	sortResults(results)
	timeline.derive()
	for i := range results {
		if r.dependsOn(results[i].Scenario, results[i].Profile, scenarios.EvidenceStaplePublished) && !timeline.staplePublishedMono.IsZero() && !results[i].DecisionAt.IsZero() {
			results[i].EnforcementLatency = results[i].DecisionAt.Sub(timeline.staplePublishedMono)
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
	if len(publishedStaple) > 0 {
		references, err := r.persistCycleArtifacts(cycleID, map[string]cycleArtifact{
			"published-staple.der": {MediaType: "application/ocsp-response", Contents: publishedStaple},
		})
		if err != nil {
			metrics.CycleTotal.WithLabelValues("error").Inc()
			return fail(PhasePersistEvidence, fmt.Errorf("runner: persisting published OCSP staple: %w", err))
		}
		report.Artifacts = append(report.Artifacts, references...)
		sort.Slice(report.Artifacts, func(i, j int) bool { return report.Artifacts[i].Path < report.Artifacts[j].Path })
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

func (r *Runner) validateEnabledRoles() error {
	oracles := 0
	clients := 0
	for _, profile := range r.Profiles {
		if !r.Config.IsEnabled(profile.Name) {
			continue
		}
		switch profile.Role {
		case profiles.RoleStatusOracle:
			oracles++
		case profiles.RoleClientExecutor:
			clients++
		}
	}
	if oracles == 0 || clients == 0 {
		return fmt.Errorf("runner: enabled profiles must include at least one status oracle and one client executor (oracles=%d clients=%d)", oracles, clients)
	}
	return nil
}

func newTimeline(revokeRequestAt, revokeAckAt time.Time) Timeline {
	return Timeline{
		RevokeRequestAt: revokeRequestAt.UTC(), RevokeAckAt: revokeAckAt.UTC(),
		revokeRequestMono: revokeRequestAt, revokeAckMono: revokeAckAt,
	}
}

func (t *Timeline) setOCSPOracleRevoked(at time.Time) {
	t.ocspOracleFirstRevokedMono = earliest(t.ocspOracleFirstRevokedMono, at)
	t.OCSPOracleFirstRevokedAt = t.ocspOracleFirstRevokedMono.UTC()
}

func (t *Timeline) setCRLOracleRevoked(at time.Time) {
	t.crlOracleFirstRevokedMono = earliest(t.crlOracleFirstRevokedMono, at)
	t.CRLOracleFirstRevokedAt = t.crlOracleFirstRevokedMono.UTC()
}

func (t *Timeline) setStapleSourceRevoked(at time.Time) {
	t.stapleSourceFirstRevokedMono = earliest(t.stapleSourceFirstRevokedMono, at)
	t.StapleSourceFirstRevokedAt = t.stapleSourceFirstRevokedMono.UTC()
}

func (t *Timeline) setStaplePublished(at time.Time) {
	t.staplePublishedMono = earliest(t.staplePublishedMono, at)
	t.StaplePublishedAt = t.staplePublishedMono.UTC()
}

func (t *Timeline) derive() {
	ack := t.revokeAckMono
	if ack.IsZero() {
		ack = t.RevokeAckAt
	}
	if ack.IsZero() {
		return
	}
	ocspAt := t.ocspOracleFirstRevokedMono
	if ocspAt.IsZero() {
		ocspAt = t.OCSPOracleFirstRevokedAt
	}
	crlAt := t.crlOracleFirstRevokedMono
	if crlAt.IsZero() {
		crlAt = t.CRLOracleFirstRevokedAt
	}
	stapleSourceAt := t.stapleSourceFirstRevokedMono
	if stapleSourceAt.IsZero() {
		stapleSourceAt = t.StapleSourceFirstRevokedAt
	}
	staplePublishedAt := t.staplePublishedMono
	if staplePublishedAt.IsZero() {
		staplePublishedAt = t.StaplePublishedAt
	}
	if !ocspAt.IsZero() {
		t.OCSPOraclePropagationLatency = ocspAt.Sub(ack)
	}
	if !crlAt.IsZero() {
		t.CRLOraclePropagationLatency = crlAt.Sub(ack)
	}
	if !stapleSourceAt.IsZero() {
		t.StapleSourcePropagationLatency = stapleSourceAt.Sub(ack)
	}
	if !stapleSourceAt.IsZero() && !staplePublishedAt.IsZero() {
		t.StapleDistributionLatency = staplePublishedAt.Sub(stapleSourceAt)
	}
}

func (r *Runner) validateOCSPStaple(staple []byte, cert *issuer.CanaryCert, expectedStatus int) error {
	if cert == nil || cert.Cert == nil || cert.IssuerCert == nil {
		return fmt.Errorf("canary certificate and issuer are required")
	}
	response, err := ocsp.ParseResponseForCert(staple, cert.Cert, cert.IssuerCert)
	if err != nil {
		return fmt.Errorf("parse OCSP staple: %w", err)
	}
	if response.Status != expectedStatus {
		return fmt.Errorf("ocsp staple status=%d, expected %d", response.Status, expectedStatus)
	}
	reason := profiles.ValidateOCSPTemporal(
		response,
		cert.Cert,
		time.Now(),
		profiles.StatusFreshnessPolicy{MaxClockSkew: r.Config.StatusFreshness.MaxClockSkew},
		profiles.OCSPFreshnessPolicy{
			RequireNextUpdate:       r.Config.OCSPFreshness.RequireNextUpdate,
			MaxAgeWithoutNextUpdate: r.Config.OCSPFreshness.MaxAgeWithoutNextUpdate,
		},
	)
	if reason != "" {
		return fmt.Errorf("ocsp staple violates temporal policy: %s", reason)
	}
	return nil
}

func (r *Runner) refreshRevokedStaple(ctx context.Context, srv *canary.Server, cert *issuer.CanaryCert) ([]byte, time.Time, time.Time, error) {
	deadline := time.Now().Add(r.Config.MaxWait)
	var lastErr error
	var lastStatus int
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return nil, time.Time{}, time.Time{}, fmt.Errorf("runner: waiting for revoked OCSP staple: %w", lastErr)
			}
			return nil, time.Time{}, time.Time{}, fmt.Errorf("runner: waiting for revoked OCSP staple: last status=%d", lastStatus)
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
			if validationErr := r.validateOCSPStaple(staple, cert, ocsp.Revoked); validationErr != nil {
				lastErr = validationErr
			} else {
				sourceRevokedAt := time.Now()
				srv.SetOCSPStaple(staple)
				publishedAt := time.Now()
				return staple, sourceRevokedAt, publishedAt, nil
			}
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
			return nil, time.Time{}, time.Time{}, ctx.Err()
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
func (r *Runner) preflight(ctx context.Context, target profiles.Target) ([]profiles.PreflightResult, map[string]time.Time, error) {
	type outcome struct {
		result       profiles.PreflightResult
		observedMono time.Time
		probeErr     error
	}

	enabled := make([]profiles.Profile, 0, len(r.Profiles))
	for _, profile := range r.Profiles {
		if r.Config.IsEnabled(profile.Name) {
			enabled = append(enabled, profile)
		}
	}
	outcomes := make(chan outcome, len(enabled))
	var wg sync.WaitGroup
	for _, p := range enabled {
		contract, ok := r.Scenarios.Contract(target.Scenario, p.Name)
		if !ok {
			return nil, nil, fmt.Errorf("preflight: profile %s has no expectation for scenario %s", p.Name, target.Scenario)
		}
		expectation := contract.Baseline
		wg.Add(1)
		go func(p profiles.Profile, expectation profiles.Expectation) {
			defer wg.Done()
			probeStartedMono := time.Now()
			attemptTarget := target
			attemptTarget.ProbeTimeout = r.Config.TimeoutFor(p.Name)
			pctx, cancel := context.WithTimeout(ctx, attemptTarget.ProbeTimeout)
			observation, err := p.Probe(pctx, attemptTarget)
			cancel()
			observedMono := time.Now()
			if err != nil {
				observation.Decision = profiles.DecisionHarnessError
				observation.Reason = profiles.ReasonHarnessFailure
			}
			result := profiles.PreflightResult{
				Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
				Decision: observation.Decision, Reason: observation.Reason,
				ExpectedDecision: expectation.Before, ExpectedReasons: expectation.BeforeReasons,
				ExpectationMet: expectation.MatchesBefore(observation), ProbeStartedAt: probeStartedMono.UTC(), ObservedAt: observedMono.UTC(), Evidence: observation.Evidence,
			}
			if err != nil {
				result.Err = err.Error()
			}
			outcomes <- outcome{result: result, observedMono: probeStartedMono, probeErr: err}
		}(p, expectation)
	}
	wg.Wait()
	close(outcomes)

	results := make([]profiles.PreflightResult, 0, len(enabled))
	observed := make(map[string]time.Time, len(enabled))
	probeErrors := make(map[string]error, len(enabled))
	for item := range outcomes {
		results = append(results, item.result)
		observed[item.result.Profile] = item.observedMono
		probeErrors[item.result.Profile] = item.probeErr
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Profile < results[j].Profile })
	for _, result := range results {
		if err := probeErrors[result.Profile]; err != nil {
			return results, observed, fmt.Errorf("preflight: profile %s errored: %w", result.Profile, err)
		}
		if !result.ExpectationMet {
			return results, observed, fmt.Errorf("preflight: profile %s produced %s/%s, expected %s/%v for scenario %s", result.Profile, result.Decision, result.Reason, result.ExpectedDecision, result.ExpectedReasons, target.Scenario)
		}
	}
	return results, observed, nil
}

func validatePreflightAge(observed map[string]time.Time, now time.Time, maxAge time.Duration) error {
	if maxAge <= 0 {
		return fmt.Errorf("preflight: max age must be positive")
	}
	for profile, at := range observed {
		if at.IsZero() {
			return fmt.Errorf("preflight: profile %s has no probe-start timestamp", profile)
		}
		if age := now.Sub(at); age > maxAge {
			return fmt.Errorf("preflight: profile %s probe started %s ago, exceeds %s", profile, age, maxAge)
		}
	}
	return nil
}

// pollClients waits only on the manifest-declared evidence boundaries for a
// profile. The implementation method does not imply a wait condition.
func (r *Runner) pollClients(ctx context.Context, target profiles.Target, revokedAt time.Time, barriers map[scenarios.EvidenceDependency]*evidenceBarrier) []profiles.Result {
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
			required, _ := r.Scenarios.Dependencies(target.Scenario, p.Name)
			requiredNames := evidenceDependencyNames(required)
			satisfiedAt, err := r.waitForEvidence(ctx, target.Scenario, p.Name, barriers)
			if err != nil {
				mu.Lock()
				results = append(results, r.harnessResult(p, target, revokedAt, requiredNames, satisfiedAt, err))
				mu.Unlock()
				return
			}
			result := r.pollOne(ctx, p, target, revokedAt)
			result.RequiredEvidence = requiredNames
			result.EvidenceSatisfiedAt = satisfiedAt
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return results
}

type evidenceBarrier struct {
	ready chan struct{}
	once  sync.Once
	mu    sync.RWMutex
	at    time.Time
	err   error
}

func newEvidenceBarrier() *evidenceBarrier {
	return &evidenceBarrier{ready: make(chan struct{})}
}

func (b *evidenceBarrier) satisfy(at time.Time) {
	b.once.Do(func() {
		b.mu.Lock()
		b.at = at
		b.mu.Unlock()
		close(b.ready)
	})
}

func (b *evidenceBarrier) fail(err error) {
	if err == nil {
		err = fmt.Errorf("evidence dependency was not satisfied")
	}
	b.once.Do(func() {
		b.mu.Lock()
		b.err = err
		b.mu.Unlock()
		close(b.ready)
	})
}

func (b *evidenceBarrier) state() (time.Time, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.at, b.err
}

func evidenceDependencyNames(values []scenarios.EvidenceDependency) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func (r *Runner) waitForEvidence(ctx context.Context, scenario profiles.Scenario, profile string, barriers map[scenarios.EvidenceDependency]*evidenceBarrier) (map[string]time.Time, error) {
	dependencies, ok := r.Scenarios.Dependencies(scenario, profile)
	if !ok {
		return nil, fmt.Errorf("profile %s has no evidence dependencies for scenario %s", profile, scenario)
	}
	satisfied := make(map[string]time.Time, len(dependencies))
	for _, dependency := range dependencies {
		barrier, ok := barriers[dependency]
		if !ok || barrier == nil || barrier.ready == nil {
			return satisfied, fmt.Errorf("profile %s requires unavailable evidence dependency %s", profile, dependency)
		}
		select {
		case <-ctx.Done():
			return satisfied, ctx.Err()
		case <-barrier.ready:
		}
		at, err := barrier.state()
		if err != nil {
			return satisfied, fmt.Errorf("profile %s waiting for %s: %w", profile, dependency, err)
		}
		if at.IsZero() {
			return satisfied, fmt.Errorf("profile %s waiting for %s: dependency closed without a satisfaction timestamp", profile, dependency)
		}
		satisfied[string(dependency)] = at.UTC()
	}
	return satisfied, nil
}

func publicationEvidence(method profiles.CheckMethod, results []profiles.Result) (time.Time, error) {
	if len(results) == 0 {
		return time.Time{}, fmt.Errorf("%s publication has no enabled status oracle", method)
	}
	var first time.Time
	var failures []string
	for _, result := range results {
		if result.Decision == profiles.DecisionReject && result.Reason == profiles.ReasonRevoked && !result.DecisionAt.IsZero() {
			first = earliest(first, result.DecisionAt)
			continue
		}
		failures = append(failures, fmt.Sprintf("%s=%s/%s expectation_met=%t error=%q", result.Profile, result.Decision, result.Reason, result.ExpectationMet, result.Err))
	}
	if !first.IsZero() {
		return first, nil
	}
	sort.Strings(failures)
	return time.Time{}, fmt.Errorf("%s publication was not confirmed: %s", method, strings.Join(failures, "; "))
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

func (r *Runner) harnessResult(p profiles.Profile, target profiles.Target, revokedAt time.Time, required []string, satisfied map[string]time.Time, err error) profiles.Result {
	contract, _ := r.Scenarios.Contract(target.Scenario, p.Name)
	expectation := contract.Baseline
	return profiles.Result{
		Profile: p.Name, Role: p.Role, Method: p.Method, Scenario: target.Scenario,
		Decision: profiles.DecisionHarnessError, Reason: profiles.ReasonHarnessFailure,
		ExpectedDecision: expectation.After, ExpectedReasons: expectation.AfterReasons,
		CertificateSerial: target.CertificateSerial, RevokeAckAt: revokedAt.UTC(),
		RequiredEvidence: required, EvidenceSatisfiedAt: satisfied, Err: err.Error(),
	}
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
			dependencies, _ := r.Scenarios.Dependencies(target.Scenario, p.Name)
			res.RequiredEvidence = evidenceDependencyNames(dependencies)
			res.EvidenceSatisfiedAt = map[string]time.Time{string(scenarios.EvidenceIssuerAck): revokedAt.UTC()}
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
		attemptTarget := target
		attemptTarget.ProbeTimeout = attemptTimeout
		observation, err := p.Probe(probeCtx, attemptTarget)
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
