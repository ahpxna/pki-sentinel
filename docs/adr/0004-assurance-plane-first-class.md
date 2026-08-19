# ADR-0004: Assurance plane as a first-class component

**Status:** Accepted — 2026-08-01

## Context

The original CYB 260 research that motivates this project was a one-off lab
measurement: a private CA, a single client platform, `tc netem` delay
injection, and a manually-run script. That produced real findings (see
`docs/benchmarks/`) but no durable capability — the moment the lab
environment was torn down, the organization had no ongoing way to know
whether its production clients were honoring revocation.

## Decision Drivers

- A measurement that runs once and is forgotten provides no operational
  value after the initial finding.
- SMEs adopting internal PKI have no existing tooling that continuously
  verifies enforcement, only tooling that issues and renews certificates.

## Considered Options

1. Publish the original research as a report/paper and let the PKI
   (Issuance plane) stand alone as the product.
2. Productize the measurement itself as `revocation-probe`, running
   continuously as part of the platform.

## Decision Outcome

Make measurement a first-class, continuously running component
(`revocation-probe` and `truststore-drift-agent`, together the Assurance
plane) rather than a one-time report. Assurance capabilities take priority
over nonessential Issuance-plane refinements when scope must be reduced.

## Consequences

- Positive: pki-sentinel continuously reports current revocation-enforcement
  results for every configured client profile.
- Negative: this is more component surface area (a second Go service, its
  own Prometheus metrics, its own Grafana dashboard, its own Dockerfile
  deviating from the distroless norm — see ADR-0006) than a PKI-only repository
  would need.
- The chaos-sweep feature (Step 3.7) exists specifically so the original
  one-off soft-fail measurement becomes a repeatable, versioned artifact
  (`docs/benchmarks/data/chaos-*.csv`) rather than a non-reproducible
  historical claim.
