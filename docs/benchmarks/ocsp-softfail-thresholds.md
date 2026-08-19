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
subcommand) reproduces this experiment on a different stack: Vault PKI
instead of OpenSSL's `openssl ocsp`, and — unlike the original single-client
run — the full seven-profile matrix instead of one client. The sweep
defaults to the same dense delay list near 2s
(`chaos.DefaultDelaysMS`: 0, 100, 500, 1000, 1500, 1700, 1900, 1950, 1960,
1970, 1980, 1990, 2000ms) specifically so new runs are comparable to the
original figures.

Each run writes `docs/benchmarks/data/chaos-<timestamp>.csv` (columns:
`delay_ms,softfail_rate`) and updates the `pki_chaos_softfail_rate{delay_ms}`
Grafana heatmap panel — the direct descendant of the original soft-fail-rate
figure.

**Where to expect agreement, and where to expect divergence:** the ground-
truth oracle profile (`openssl-ocsp-direct`) should reproduce a similar
transition band, since it uses the same tool as the original run. The other
six profiles are expected to diverge — that divergence *is* the new data
this repo adds: different clients (Go stdlib, `curl` without `--cert-status`,
Python `requests`) don't even attempt the check that would put them in the
transition band in the first place, so their soft-fail rate is close to
100% at every delay level, independent of network conditions.

## Operational implication

Because the enforcement boundary is latency-dependent and jittery, an
adversary does not need to block the OCSP path — degrading it is
sufficient. Each mitigation below maps to a concrete feature in this repo:

| Mitigation | Where it lives |
|---|---|
| Prefer short-lived certificates | [ADR-0003](../adr/0003-short-lived-certs-over-revocation.md); 24h leaf TTL, 10m canary TTL |
| Staple OCSP | `internal/canary/server.go` stapling modes (`on`/`off`/`stale`) |
| Hard-fail on high-risk paths | `go-tls-ocsp` profile's must-staple-style behavior; documented per-profile expectations in `internal/profiles/registry.go` |
| Monitor revocation enforcement continuously | The entire Assurance plane — `revocation-probe` running on a schedule, not as a one-off script |
