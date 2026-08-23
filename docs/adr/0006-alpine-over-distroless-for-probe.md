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
other clients. Chaos injection is implemented in-process and does not add an
operating-system package or Linux capability.

## Decision Drivers

- The product's core value proposition (an empirical matrix of real client
  behavior) requires real client binaries in the image.
- Attack-surface reduction remains a requirement, subject to the runtime
  dependencies needed by this service.

## Considered Options

1. Distroless, and reimplement every profile in pure Go. Rejected: a
   Go reimplementation of curl's or Python requests' revocation behavior is
   not evidence of observed curl or Python Requests behavior.
2. Alpine with exactly the tools the profiles need
   (`curl openssl python3 py3-requests ca-certificates`) and a non-root user.

## Decision Outcome

Use Alpine with only the listed packages, a non-root `probe` user, and CI
image scanning through the `security-scan.yml` image-scan job. `SECURITY.md`
links to this documented exception to the distroless standard.

## Consequences

- Positive: profile results are evidence about real client software, not
  about this project's reimplementation of it.
- Negative: larger image and non-trivial package surface (`python3`, `curl`,
  `openssl`). The image is digest-pinned and scanned, but Alpine packages
  remain rebuild-time inputs until a snapshot repository is introduced.
- Positive: the responder-only fault proxy requires no `NET_ADMIN` capability
  and cannot delay unrelated container traffic.
