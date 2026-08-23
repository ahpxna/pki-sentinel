# Assurance Experiment Roadmap

This document defines the next research increments without changing the
meaning of existing measurements.

## Established controls

- The revocation acknowledgement, direct OCSP observation, full-CRL
  observation, stapled-status publication, and client decision are separate
  timeline boundaries.
- Every retained result references raw certificate, command, OCSP, or CRL
  artifacts by SHA-256.
- Scenario conformance describes observed baseline behavior. Policy conformance
  is separately recorded and may be enforced only when the deployment enables
  `policy.enforce`.
- A chaos trial records validity independently of whether the direct OCSP
  oracle confirms revocation.

## Phase 1: declarative scenarios

Replace hard-coded profile expectations with versioned YAML manifests. A
manifest must specify:

```yaml
id: revoked-staple-v1
evidence_dependencies:
  ocsp_direct: issuer_acknowledgement
  crl: issuer_acknowledgement
  ocsp_stapled: staple_published
profiles:
  go-hardfail-ocsp:
    baseline: { decision: REJECT, reasons: [REVOKED] }
    policy:   { decision: REJECT, reasons: [REVOKED, MISSING_STATUS, INVALID_STATUS, STALE_STATUS] }
```

CI should validate the manifest schema, require each enabled profile to have a
baseline and policy contract, and archive the manifest digest with the signed
cycle report.

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
