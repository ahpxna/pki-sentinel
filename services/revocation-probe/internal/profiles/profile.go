// Package profiles defines the assurance domain model shared by the
// revocation probe. A decision records what a relying party did; a reason
// records why the harness believes it made that decision. Status oracles are
// explicitly separated from client executors.
package profiles

import (
	"context"
	"time"
)

// Role identifies whether an executor observes CA status directly or behaves
// as a relying-party TLS client.
type Role string

const (
	RoleStatusOracle   Role = "status_oracle"
	RoleClientExecutor Role = "client_executor"
)

// Decision is the normalized outcome of an assurance observation.
type Decision string

const (
	DecisionAccept       Decision = "ACCEPT"
	DecisionReject       Decision = "REJECT"
	DecisionInconclusive Decision = "INCONCLUSIVE"
	DecisionHarnessError Decision = "HARNESS_ERROR"
)

// Reason explains a decision without conflating revocation enforcement with
// unrelated network, TLS, or harness failures.
type Reason string

const (
	ReasonStatusGood        Reason = "STATUS_GOOD"
	ReasonRevoked           Reason = "REVOKED"
	ReasonExpired           Reason = "EXPIRED"
	ReasonMissingStatus     Reason = "MISSING_STATUS"
	ReasonInvalidStatus     Reason = "INVALID_STATUS"
	ReasonStaleStatus       Reason = "STALE_STATUS"
	ReasonUnknownStatus     Reason = "UNKNOWN_STATUS"
	ReasonNoRevocationCheck Reason = "NO_REVOCATION_CHECK"
	ReasonNetworkFailure    Reason = "NETWORK_FAILURE"
	ReasonTLSFailure        Reason = "TLS_FAILURE"
	ReasonClientPolicy      Reason = "CLIENT_POLICY"
	ReasonHarnessFailure    Reason = "HARNESS_FAILURE"
)

// CheckMethod describes how (if at all) a profile verifies revocation status.
type CheckMethod string

const (
	MethodOCSPDirect  CheckMethod = "ocsp_direct"  // query the responder directly, no TLS
	MethodOCSPStapled CheckMethod = "ocsp_stapled" // must-staple / stapled response
	MethodCRL         CheckMethod = "crl"
	MethodNone        CheckMethod = "none"
)

// Scenario identifies a stable assurance experiment. Values are bounded so
// they are safe to use as Prometheus labels.
type Scenario string

const (
	ScenarioRevokedStaple    Scenario = "revoked_staple"
	ScenarioMissingStaple    Scenario = "missing_staple"
	ScenarioCachedGoodStaple Scenario = "cached_good_staple"
)

// Target describes the ephemeral canary TLS endpoint a profile should probe.
type Target struct {
	Host string // SNI hostname, e.g. canary-<uuid>.canary.internal
	// ConnectHost is the network address used to reach Host. It is empty for
	// local execution (127.0.0.1) and names the probe service when a profile
	// runs in an isolated client-executor container.
	ConnectHost       string
	Port              int
	CAChainPEM        string // PEM bundle: issuing CA + root CA
	IssuerPEM         string // issuing CA used to validate OCSP responses
	OCSPURL           string
	CRLURL            string
	CertificateSerial string
	Scenario          Scenario
}

// CommandEvidence preserves enough subprocess evidence for independent
// diagnosis without putting unbounded certificate identifiers into metrics.
type CommandEvidence struct {
	Client        string `json:"client,omitempty"`
	Executor      string `json:"executor,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	TLSBackend    string `json:"tls_backend,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
	StdoutSHA256  string `json:"stdout_sha256,omitempty"`
	StderrSHA256  string `json:"stderr_sha256,omitempty"`
}

// Observation is returned by one oracle or client execution attempt.
type Observation struct {
	Decision Decision        `json:"decision"`
	Reason   Reason          `json:"reason"`
	Evidence CommandEvidence `json:"evidence,omitempty"`
}

// Expectation defines the decision a profile should produce before and after
// revocation for a scenario. It is used both as a pre-flight invariant and as
// a security-regression assertion.
type Expectation struct {
	Before        Decision
	BeforeReasons []Reason
	After         Decision
	AfterReasons  []Reason
}

func reasonAllowed(reason Reason, allowed []Reason) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if reason == candidate {
			return true
		}
	}
	return false
}

// MatchesBefore and MatchesAfter validate both dimensions of a scenario
// contract. An empty reason list is reserved for synthetic unit-test profiles.
func (e Expectation) MatchesBefore(observation Observation) bool {
	return observation.Decision == e.Before && reasonAllowed(observation.Reason, e.BeforeReasons)
}

func (e Expectation) MatchesAfter(observation Observation) bool {
	return observation.Decision == e.After && reasonAllowed(observation.Reason, e.AfterReasons)
}

// Profile is one status oracle or relying-party client executor.
type Profile struct {
	Name         string
	Role         Role
	Method       CheckMethod
	Description  string
	Expectations map[Scenario]Expectation
	Probe        func(ctx context.Context, target Target) (Observation, error)
}

// Expected returns the scenario-specific contract for this profile.
func (p Profile) Expected(scenario Scenario) (Expectation, bool) {
	expectation, ok := p.Expectations[scenario]
	return expectation, ok
}

// Result is the durable evidence record for one profile in one cycle.
type Result struct {
	Profile           string          `json:"profile"`
	Role              Role            `json:"role"`
	Method            CheckMethod     `json:"method"`
	Scenario          Scenario        `json:"scenario"`
	Decision          Decision        `json:"decision"`
	Reason            Reason          `json:"reason"`
	ExpectedDecision  Decision        `json:"expected_decision"`
	ExpectedReasons   []Reason        `json:"expected_reasons,omitempty"`
	ExpectationMet    bool            `json:"expectation_met"`
	CertificateSerial string          `json:"certificate_serial"`
	RevokeAckAt       time.Time       `json:"revoke_ack_at"`
	DecisionAt        time.Time       `json:"decision_at,omitempty"`
	DecisionLatency   time.Duration   `json:"decision_latency_ns,omitempty"`
	Attempts          int             `json:"attempts"`
	Evidence          CommandEvidence `json:"evidence,omitempty"`
	Err               string          `json:"error,omitempty"`
}
