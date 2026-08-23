# OCSP soft-fail thresholds

## Prior work (original testbed)

**Methodology.** A private OpenSSL CA and an Apache HTTPS server, a macOS
client polling via `curl` with OCSP verification enabled, `tc netem` delay
injection on the path to the OCSP responder. Detection time was defined as
the interval between the CA-side revocation timestamp and the first
client-side verification failure — the same discipline this repo uses for
`t_response` in `internal/issuer/vault.go`'s `Revoke` method.

**Findings.**

The aggregate rates below are transcribed in
[`data/prior-ocsp-softfail-summary.csv`](data/prior-ocsp-softfail-summary.csv).
The original per-trial observations and sample sizes are unavailable, so no
confidence interval is claimed.

- Detection was stable and fast at low injected delay.
- Sharply unstable in the ~1950–2000ms band: soft-fail rate measured 0% up
  to ~1955ms, then 100% at 1960ms, 0% at 1970ms, 67% at 1980ms, and 100% at
  1990ms and 2000ms.
- Detection-time distributions near 1950–1955ms showed heavy right tails
  past 60 seconds.

**Headline interpretation:** the soft-fail boundary is a jittery transition
band, not a clean threshold, so mean detection time alone understates the
risk — the tail is the risk. This is exactly why
`pki_revocation_detection_seconds` is exported as a histogram (with buckets
dense enough to resolve p95/p99 behavior) rather than an average.

### Limitations of the prior run

Small trial counts at some delay levels, a single client platform (macOS
`curl`), and a single CA implementation (OpenSSL, not Vault). Stated
plainly: acknowledged limitations read as rigor, unacknowledged ones read
as inexperience.

## Reproduction with pki-sentinel

`make chaos-sweep` (backed by `internal/chaos` and the `probe chaos sweep`
subcommand) runs a narrower experiment on a different stack: Vault PKI and the
`openssl-ocsp-direct` status oracle. An in-process reverse proxy delays only
requests to `/v1/pki_int/ocsp`; issuer, CRL, and target-service traffic bypasses
the proxy. It does not execute the client matrix. Results therefore describe a
direct OCSP oracle under responder-scoped latency and must not be generalized
to TLS client soft-fail behavior. The sweep defaults to the same dense delay list near 2s
(`chaos.DefaultDelaysMS`: 0, 100, 500, 1000, 1500, 1700, 1900, 1950, 1960,
1970, 1980, 1990, 2000ms) specifically so new runs are comparable to the
original figures.

Each run writes `docs/benchmarks/data/chaos-<timestamp>.csv` with columns
`delay_ms,oracle_failure_rate`. The one-shot process is intentionally not a
Prometheus scrape target; a run becomes durable evidence only when its raw CSV
is reviewed and committed. The name avoids presenting direct-oracle failures
as relying-party soft-fails.

The experiment is useful for validating the responder fault layer and OCSP
oracle. Separate digest-pinned client environments and client-specific fault
paths are required before the project can claim relying-party transition
thresholds.

## Operational implication

Because the enforcement boundary is latency-dependent and jittery, an
adversary does not need to block the OCSP path — degrading it is
sufficient. Each mitigation below maps to a concrete feature in this repo:

| Mitigation | Where it lives |
|---|---|
| Prefer short-lived certificates | [ADR-0003](../adr/0003-short-lived-certs-over-revocation.md); 24h leaf TTL, 10m canary TTL |
| Staple OCSP | `internal/canary/server.go` stapling modes (`on`/`off`/`stale`) |
| Hard-fail on high-risk paths | `go-hardfail-ocsp` custom validator; documented scenario contracts in `internal/profiles/registry.go` |
| Monitor revocation enforcement continuously | The entire Assurance plane — `revocation-probe` running on a schedule, not as a one-off script |
