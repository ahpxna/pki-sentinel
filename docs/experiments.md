# Assurance Experiment Roadmap

This document defines the next research increments without changing the
meaning of existing measurements.

## Established controls

- The revocation acknowledgement, direct OCSP observation, full-CRL
  observation, stapled-status publication, and client decision are separate
  timeline boundaries.
- Every retained result references raw certificate, command, OCSP, or CRL
  artifacts by SHA-256.
- BEFORE/preflight observations are retained alongside post-revocation results,
  so a verifier can independently check the causal guard for each profile.
- Every cycle that reaches a run identity is reportable even when the harness
  fails; `valid` and `phase` keep invalid trials in the experiment denominator.
- Scenario conformance describes observed baseline behavior. Policy conformance
  is separately recorded and may be enforced only when the deployment enables
  `policy.enforce`.
- A chaos trial records validity independently of whether the direct OCSP
  oracle confirms revocation.

## Phase 1: declarative scenarios

Implemented in [`services/revocation-probe/scenarios/`](../services/revocation-probe/scenarios/).
Each version-1 manifest is a strict YAML input; its canonical JSON SHA-256 is
reported as `scenario_digest` and bound into the signed attestation statement.
The runtime rejects unknown fields, decisions, reasons, evidence dependencies,
duplicate scenarios or profile keys, duplicate/empty reason or dependency
lists, incompatible decision/reason pairs, orphan dependency declarations,
contracts missing an enabled profile, and publication dependencies with no
enabled status-oracle producer.

The three baseline manifests preserve the established `revoked_staple`,
`missing_staple`, and `cached_good_staple` observations:

```yaml
id: revoked_staple
version: 1
execution:
  stapling: on
evidence_dependencies:
  openssl-ocsp-direct: [issuer_ack]
  curl-cert-status: [staple_published]
profiles:
  go-hardfail-ocsp:
    baseline:
      before: {decision: ACCEPT, reasons: [STATUS_GOOD]}
      after: {decision: REJECT, reasons: [REVOKED]}
    policy:
      after: {decision: REJECT, reasons: [REVOKED, MISSING_STATUS, INVALID_STATUS, STALE_STATUS, FUTURE_STATUS, UNKNOWN_STATUS, MISSING_FRESHNESS_BOUND]}
```

The selected `probe run --scenario <id>` manifest controls its canary stapling
mode and each client profile's evidence boundary. For example,
`staple_published` holds a profile until a revoked staple is published, while
`issuer_ack` allows it to begin immediately after issuer acknowledgement.
Reason/dependency list ordering is canonicalized before digesting because those
fields are semantic sets, not execution-order controls. CI validates production
manifests and the unit suite asserts exact parity with the pre-manifest
contracts.

## Phase 2: client diversity matrix

Build independently versioned executor images rather than treating several
tools from one Alpine package set as independent platforms. Record image
digest, OS, architecture, client version, TLS backend, and profile revision.
Initial cells: OpenSSL, libcurl with its TLS backend, Go releases, Python
requests/urllib3, and a browser only where its revocation model is meaningful
for a private CA.

## Phase 3: fault and status matrix

For every client image, run bounded trials across delayed, dropped, reset,
timeout, HTTP 500, malformed, missing, stale, future-dated, unknown, and
revoked status responses. Report attempted trials, valid trials, harness
errors, and confidence intervals; do not claim client soft-fail thresholds
from direct-oracle-only data.

## Phase 4: reproducibility and supply chain

Archive a scenario manifest, signed report, artifact hashes, container image
digests, configuration revision, and raw trial CSV as one experiment bundle.
Use a KMS/HSM-backed signer or a DSSE/in-toto-compatible envelope before
publishing results outside the controlled environment.
