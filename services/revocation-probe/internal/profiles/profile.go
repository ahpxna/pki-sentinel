// Package profiles defines the core domain model shared across the
// revocation-probe: outcomes, check methods, profile definitions, and
// per-cycle results.
package profiles

import (
	"context"
	"time"
)

// Outcome is the result of a single client profile's revocation check.
type Outcome string

const (
	// OutcomeRejected means the client correctly refused the revoked cert.
	OutcomeRejected Outcome = "rejected"
	// OutcomeAccepted means the client soft-failed: it used a revoked cert.
	OutcomeAccepted Outcome = "accepted"
	// OutcomeError means the harness itself failed. Not a security signal.
	OutcomeError Outcome = "error"
)

// CheckMethod describes how (if at all) a profile verifies revocation status.
type CheckMethod string

const (
	MethodOCSPDirect  CheckMethod = "ocsp_direct"  // query the responder directly, no TLS
	MethodOCSPStapled CheckMethod = "ocsp_stapled" // must-staple / stapled response
	MethodCRL         CheckMethod = "crl"
	MethodNone        CheckMethod = "none" // client performs no revocation check
)

// Target describes the ephemeral canary TLS endpoint a profile should probe.
type Target struct {
	Host       string // SNI hostname, e.g. canary-<uuid>.canary.internal
	Port       int
	CAChainPEM string // PEM bundle: issuing CA + root CA
	OCSPURL    string
	CRLURL     string
}

// Profile is a single client-behavior probe.
type Profile struct {
	Name        string
	Method      CheckMethod
	Description string
	// Expected is the baseline outcome documented in profiles.yaml / the
	// Phase 3 client-profile table; used by tests and the pre-flight guard.
	Expected string

	// Probe returns whether the client rejected the connection to Target.
	// A nil error with OutcomeAccepted/OutcomeRejected is the normal path;
	// a non-nil error always implies OutcomeError.
	Probe func(ctx context.Context, target Target) (Outcome, error)
}

// Result is the outcome of a single profile within a single probe cycle.
type Result struct {
	Profile      string        `json:"profile"`
	Method       CheckMethod   `json:"method"`
	Outcome      Outcome       `json:"outcome"`
	RevokedAt    time.Time     `json:"revoked_at"`
	DetectedAt   time.Time     `json:"detected_at,omitempty"`
	DetectionDur time.Duration `json:"detection_duration_ns,omitempty"`
	Attempts     int           `json:"attempts"`
	Err          string        `json:"error,omitempty"`
}
