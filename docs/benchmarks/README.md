# Benchmarks

This directory holds the research chapter behind pki-sentinel's Assurance
plane. Two documents, each clearly separating a prior one-off lab
measurement from its reproduction as a repeatable feature in this repo:

- [`ocsp-softfail-thresholds.md`](ocsp-softfail-thresholds.md) — the OCSP
  soft-fail transition-band findings, reproduced via `make chaos-sweep`.
- [`trusted-ca-mitm.md`](trusted-ca-mitm.md) — the trusted-CA MITM findings,
  and why detection has to happen at the trust-store layer
  (`truststore-drift-agent`), not the TLS layer.

Every numeric claim in these documents traces to a committed CSV in
[`data/`](data/) or a cited figure in [`figures/`](figures/). No number
appears without a source.
