# ADR-0006: Alpine over distroless for the revocation-probe container

**Status:** Accepted — 2026-08-01

## Context

Every other Go service in this repository (`demo-api`, `truststore-drift-agent`)
ships on `gcr.io/distroless/static-debian12:nonroot` — no shell, no package
manager, minimal attack surface. `revocation-probe` cannot follow that
pattern: several of its client profiles (`openssl-ocsp-direct`,
`curl-cert-status`, `curl-default`, `python-requests`) are deliberately
*subprocess wrappers around real client tooling*. The profile matrix must
observe actual, unmodified client behavior rather than a Go approximation of
other clients. The chaos
sweep (Step 3.7) also shells out to `tc`.

## Decision Drivers

- The product's core value proposition (an empirical matrix of real client
  behavior) requires real client binaries in the image.
- Attack-surface reduction remains a requirement, subject to the runtime
  dependencies needed by this service.

## Considered Options

1. Distroless, and reimplement every profile in pure Go. Rejected: a
   Go reimplementation of curl's or Python requests' revocation behavior is
   not evidence of observed curl or Python Requests behavior.
2. Alpine 3.20 with exactly the tools the profiles need
   (`curl openssl python3 py3-requests iproute2 ca-certificates`), non-root
   user, `tc` capability scoped via file capability (`setcap
   cap_net_admin=+ep`) rather than running the whole container as root.

## Decision Outcome

Use Alpine with only the listed packages, a non-root `probe` user, and CI
image scanning through the `security-scan.yml` image-scan job. `SECURITY.md`
links to this documented exception to the distroless standard.

## Consequences

- Positive: profile results are evidence about real client software, not
  about this project's reimplementation of it.
- Negative: larger image, non-trivial package surface (`python3`, `curl`,
  `openssl`), all of which are pinned and scanned. `NET_ADMIN` is
  compose-level `cap_add` on this one service only — no other service in
  the stack has it.
