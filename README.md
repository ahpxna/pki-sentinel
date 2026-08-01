# pki-sentinel

**Internal PKI for SMEs that continuously proves your clients actually reject revoked certificates.**

![CI](https://github.com/OWNER/pki-sentinel/actions/workflows/ci.yml/badge.svg)
![Security Scan](https://github.com/OWNER/pki-sentinel/actions/workflows/security-scan.yml/badge.svg)
![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/OWNER/pki-sentinel/badge)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go Report Card](https://goreportcard.com/badge/github.com/OWNER/pki-sentinel)
![Latest Release](https://img.shields.io/github/v/release/OWNER/pki-sentinel)

![demo](docs/images/demo.gif)

*(Regenerate the GIF with `vhs docs/images/demo.tape` — script committed at [`docs/images/demo.tape`](docs/images/demo.tape).)*

## Why I built this

Most SMEs running internal services either skip TLS entirely, hand-roll a
self-signed CA nobody rotates, or stand up a PKI and never look at it again.
Certificates get issued once and renewed manually, if at all.

Of the organizations that *do* deploy certificate revocation, almost none
verify that their clients actually honor it. Revocation checking is treated
as a checkbox — CRL distribution point configured, OCSP responder running —
rather than a property that has to be continuously measured against real
client behavior.

That gap is not hypothetical. A controlled private-CA testbed (see
[`docs/benchmarks/`](docs/benchmarks/)) showed the OCSP soft-fail transition
is a narrow, jittery band rather than a clean threshold — soft-fail rates
reached 100% at several injected-delay points near the client timeout, not
just "eventually, past some clean cutoff." The same testbed showed a
trusted-CA MITM succeeds in 100% of trials with zero client-side warning,
because that failure mode is invisible at the TLS layer by design. Both
findings, and their reproduction inside this repo, are written up in
[`docs/benchmarks/`](docs/benchmarks/).

pki-sentinel is what a PKI looks like when "does revocation actually work"
is a continuously measured product feature (the **Assurance plane**), not a
one-off finding from a lab exercise.

## Quick start (3 commands)

```bash
cp .env.example .env
make up
make bootstrap
```

Then see the headline finding for yourself:

```bash
make demo-revoke
```

## Architecture

pki-sentinel has three planes. The Assurance plane is the differentiator —
see [`docs/architecture.md`](docs/architecture.md) for the full diagram and
[ADR-0004](docs/adr/0004-assurance-plane-first-class.md) for why.

| Plane | Responsibility |
|---|---|
| **Issuance** | Vault/OpenBao PKI (Root + Intermediate), ACME endpoint, Traefik edge, short-lived certs |
| **Assurance** | `revocation-probe` continuously issues a canary cert, revokes it, and measures whether each client profile actually rejects it. `truststore-drift-agent` detects unauthorized root CA installation. |
| **Governance** | Prometheus/Grafana/Alertmanager, Wazuh custom decoders for Vault audit logs, OPA policy gates in CI |

## What you get

- A production-shaped Vault PKI hierarchy (Raft storage, transit
  auto-unseal, offline-style root, ACME-issuing intermediate) fully
  declared in Terraform.
- Traefik obtaining certificates from Vault's ACME endpoint with zero
  manual steps.
- A continuous revocation-enforcement probe across 7 real client
  configurations (`openssl`, `curl` with and without `--cert-status`, Go
  `crypto/tls`, Python `requests`, CRL-based checking).
- A repeatable `tc netem` latency-injection sweep that reproduces the OCSP
  soft-fail transition-band finding on demand.
- A trust-store drift detector for the one MITM scenario that TLS itself
  cannot see.
- Prometheus/Grafana/Alertmanager wired end-to-end, including a working
  alert path even without a real Slack workspace.
- Wazuh decoders/rules over Vault's audit log, keyed on the events that
  actually matter (a root-CA write outside bootstrap, AppRole brute force,
  policy changes).
- A CI pipeline that gates on security *properties* (an integration test
  that asserts real clients actually detect revocation), not just lint.

## Try the demo

```bash
make demo-revoke              # one probe cycle; detection table with soft-fail rows
make chaos-sweep              # latency sweep; writes docs/benchmarks/data/chaos-*.csv
make truststore-drift-demo    # installs a synthetic rogue CA, shows detection (exit=1)
```

## Client profile results table

The honest matrix — which clients check revocation, and which don't. This
table is the single most compelling artifact in this repo; `make
demo-revoke` reproduces it live against your own stack.

| Profile | Method | Expected baseline |
|---|---|---|
| `openssl-ocsp-direct` | OCSP (direct query) | **rejected** — ground-truth oracle |
| `curl-cert-status` | OCSP (stapled) | rejected when stapling on; **accepted** when stapling off |
| `curl-default` | none | **accepted** — curl does no revocation check by default |
| `go-tls-default` | none | **accepted** — Go stdlib does not check revocation |
| `go-tls-ocsp` | OCSP (stapled) | rejected when stapled |
| `python-requests` | none | **accepted** |
| `crl-check` | CRL | rejected after the CRL rebuild interval |

Most default client configurations accept a revoked certificate
indefinitely. That is not a bug in the harness — it is this product's
reason to exist.

## Production notes

This deployment makes several deliberate, documented shortcuts for demo
convenience. None of them are hidden — see also `SECURITY.md` and
`docs/threat-model.md`.

| Demo shortcut | Risk | Production fix |
|---|---|---|
| Root CA online in Vault | root key compromise = total trust failure | offline root on HSM/smartcard; sign the intermediate manually, annually |
| Transit auto-unseal via a second Vault | seal Vault compromise unseals everything | AWS KMS / GCP KMS / Azure Key Vault / HSM |
| Vault listener `tls_disable = true` | plaintext on the Docker bridge | TLS on the listener with a bootstrap cert |
| Recovery keys in `.data/vault-init.json` | plaintext key material on disk | PGP-encrypted shares distributed to separate key holders |
| `GRAFANA_ADMIN_PASSWORD` in `.env` | trivial credential | SSO/OIDC |
| ACME with no External Account Binding | any workload on the network can request a cert | `eab_policy: always-required` |

## Roadmap

- Kubernetes/Helm chart (see [ADR-0005](docs/adr/0005-compose-over-kubernetes.md))
- HSM-backed root CA
- cert-manager issuer for the Vault PKI backend
- Windows trust-store drift agent
- EST/SCEP support alongside ACME

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

## Acknowledgements

Built on HashiCorp Vault, Traefik, Prometheus, Grafana, and Wazuh. The
benchmark methodology in `docs/benchmarks/` builds on a prior private-CA/
`tc netem` research testbed (CYB 260 coursework); see
`docs/benchmarks/ocsp-softfail-thresholds.md` and
`docs/benchmarks/trusted-ca-mitm.md` for the full writeup and its
limitations.

## Prior work

- `docs/benchmarks/ocsp-softfail-thresholds.md`
- `docs/benchmarks/trusted-ca-mitm.md`
