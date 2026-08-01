# ADR-0005: Docker Compose over Kubernetes for v1

**Status:** Accepted — 2026-08-01

## Context

pki-sentinel targets small and medium enterprises evaluating internal PKI
for the first time. The single biggest predictor of whether anyone actually
runs an open-source infrastructure project is clone-to-value time (Step 6.7
explicitly times this and treats >3 minutes as a defect).

## Decision Drivers

- Target audience (SME operators) is unlikely to have a Kubernetes cluster
  standing by just to evaluate a PKI demo.
- Docker Compose is close to universally available wherever Docker is.
- Kubernetes adds real value (multi-node HA, autoscaling, native secret
  rotation via operators) that this v1 does not need to demonstrate the
  core Assurance-plane thesis.

## Considered Options

1. Kubernetes + Helm chart as the only supported runtime.
2. Docker Compose as the only supported runtime for v1, Kubernetes/Helm
   deferred to the roadmap.
3. Support both from day one.

## Decision Outcome

Docker Compose only for v1 (explicitly out of scope in the master plan's
global contract: *"Kubernetes is explicitly out of scope for this plan"*).
Kubernetes/Helm is listed in the README roadmap as a deliberate future step,
not an oversight.

## Consequences

- Positive: `cp .env.example .env && make up && make demo-revoke` is a
  three-command path to the headline finding, achievable on a laptop with
  only Docker installed.
- Negative: no native HA/rolling-update story; the `vault-seal` container
  and the Raft single-node storage are both single points of failure,
  which is acceptable for a demo/reference deployment but called out
  explicitly in `SECURITY.md` and the README's "Production notes".
