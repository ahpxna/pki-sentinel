# Benchmarks

This directory holds the research chapter behind pki-sentinel's Assurance
plane. Two documents, each clearly separating a prior one-off lab
measurement from its reproduction as a repeatable feature in this repository:

- [`ocsp-softfail-thresholds.md`](ocsp-softfail-thresholds.md) — prior OCSP
  client soft-fail findings plus the narrower direct-oracle latency experiment
  available through `make chaos-sweep`.
- [`trusted-ca-mitm.md`](trusted-ca-mitm.md) — the trusted-CA MITM findings,
  and why detection has to happen at the trust-store layer
  (`truststore-drift-agent`), not the TLS layer.

Every numeric claim in these documents traces to a committed CSV in
[`data/`](data/). The prior-work CSVs are explicitly labeled as transcribed
aggregate summaries because the original per-trial dataset is unavailable;
new reproduction runs must commit their raw output before their results are
cited.
