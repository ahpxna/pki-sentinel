# ADR-0003: Short-lived certificates over reliance on revocation

**Status:** Accepted — 2026-08-01

## Context

pki-sentinel's own benchmark data (`docs/benchmarks/ocsp-softfail-thresholds.md`)
shows that revocation checking, even when correctly configured end-to-end,
is not a reliable control: most default client configurations never check
revocation status at all, and even the ones that do exhibit a jittery
soft-fail transition band under network degradation rather than a clean
threshold.

## Decision Drivers

- The project's own measurement data argues against treating revocation as
  the primary control.
- 24-hour leaf TTLs (`leaf_max_ttl_hours` in `terraform/bootstrap/variables.tf`)
  bound the blast radius of a compromised key to at most one day regardless
  of whether any client ever checks a CRL or OCSP responder.

## Considered Options

1. Rely primarily on revocation (CRL/OCSP), treat short TTLs as a
   nice-to-have.
2. Treat short-lived certificates as the primary control, and revocation as
   defense in depth layered on top.

## Decision Outcome

Short-lived certificates (`server`/`client` roles: 24h; `canary`: 10m) are
the primary control. Revocation, CRL/OCSP, and the entire Assurance plane
provide defense in depth and continuously measure revocation enforcement.
Containment of a compromised key does not depend on revocation availability.

The Assurance plane (`revocation-probe`) measures the revocation layer because
its behavior varies by client implementation and network conditions.

## Consequences

- Positive: a compromised key is self-limiting even if every client in the
  fleet ignores revocation entirely.
- Negative: shorter TTLs mean more frequent renewal traffic against Vault;
  `demo-api` schedules renewal at 2/3 of TTL specifically to keep this
  smooth rather than bursty.
- This ordering (short TTL first, revocation second) is why the canary
  role's TTL (10m) is even shorter than the leaf roles' — the probe cycle
  needs to complete, revoke, and observe detection well within a single
  leaf TTL window.
