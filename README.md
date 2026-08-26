# pki-sentinel

**Continuous relying-party assurance for private PKI.**

![CI](https://github.com/ahpxna/pki-sentinel/actions/workflows/ci.yml/badge.svg)
![Security Scan](https://github.com/ahpxna/pki-sentinel/actions/workflows/security-scan.yml/badge.svg)
![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ahpxna/pki-sentinel/badge)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go Report Card](https://goreportcard.com/badge/github.com/ahpxna/pki-sentinel)
![Latest Release](https://img.shields.io/github/v/release/ahpxna/pki-sentinel)

The terminal demo recording is reproducible with
[`docs/images/demo.tape`](docs/images/demo.tape) after the stack passes
`make bootstrap`.

## Rationale

Certificate authorities answer whether a certificate has been revoked. They do
not prove that a specific version of curl, Go, Python, OpenSSL, or an application
runtime will enforce that status. PKI Sentinel measures that missing security
property:

```text
issuer acknowledges revocation
        -> status oracle confirms REVOKED
        -> real relying-party client executes
        -> decision + reason + environment evidence
        -> scenario contract passes or reports a security regression
```

That gap is not hypothetical. A controlled private-CA testbed (see
[`docs/benchmarks/`](docs/benchmarks/)) showed the OCSP soft-fail transition
is a narrow, jittery band rather than a clean threshold — soft-fail rates
reached 100% at several injected-delay points near the client timeout rather
than only beyond a stable cutoff. The same testbed showed a
trusted-CA MITM succeeds in 100% of trials with zero client-side warning,
because that failure mode is invisible at the TLS layer by design. Both
findings and their reproduction in this repository are documented in
[`docs/benchmarks/`](docs/benchmarks/).

PKI Sentinel treats Vault as the first issuer adapter and revocation enforcement
as the core product. Issuance breadth is secondary to evidence correctness.

## Quick start (3 commands)

Prerequisites: Docker Engine/Desktop with Compose v2, Terraform 1.9.5,
`curl`, and `jq`.

```bash
cp .env.example .env
make up
make bootstrap
```

Run the primary revocation-enforcement demonstration:

```bash
make demo-revoke
```

## Architecture

pki-sentinel has three planes. The Assurance plane is the differentiator —
see [`docs/architecture.md`](docs/architecture.md) for the full diagram and
[ADR-0004](docs/adr/0004-assurance-plane-first-class.md) for why.

| Plane | Responsibility |
|---|---|
| **Issuance** | Vault PKI adapter, root and intermediate authorities, ACME endpoint, Traefik edge, short-lived canaries |
| **Assurance** | Scenario controller, isolated OCSP/CRL status oracles and relying-party executors, decision/reason evidence, signed attestations, trust-policy conformance |
| **Governance** | Bounded Prometheus metrics, Grafana assurance matrix, Alertmanager, signed trust baselines, CI policy and Wazuh fixture gates |

## Included capabilities

- A production-shaped Vault PKI hierarchy (Raft storage, transit
  auto-unseal, offline-style root, ACME-issuing intermediate) fully
  declared in Terraform.
- Traefik obtaining certificates from Vault's ACME endpoint with zero
  manual steps.
- An assurance engine that separates OCSP/CRL status oracles from five
  relying-party/client checks and records `decision`, `reason`, scenario,
  client fingerprint, output hashes, exit code, certificate serial, revocation
  acknowledgement, separate status/publication/enforcement timings, and durable
  raw artifacts in JSON evidence.
- Correct `curl --cert-status` semantics: missing, invalid, and revoked OCSP
  status all reject instead of being misclassified as acceptance.
- Both Go's default TLS behavior and a separately named custom
  `go-hardfail-ocsp` validator.
- A one-shot, responder-scoped fault proxy supporting latency, connection
  drop/reset, timeout, HTTP 500, and malformed OCSP response injection. It
  accepts only the OCSP path, so no `NET_ADMIN` capability is required and
  issuer, CRL, and target-service traffic remain unaffected.
- One network-isolated executor container per status-oracle or client profile.
  The controller runs no profile subprocesses when deployed through Compose.
- Versioned, strict scenario manifests plus a canonical digest of the effective
  runtime profile configuration. Both digests are included in every cycle report
  and bound into Ed25519-signed, tamper-evident assurance-report envelopes, with
  an offline verification command.
- A trust-store exporter with `/metrics` and `/events`, signed-baseline
  verification, and detection of added, removed, changed, expired, and
  expiring roots.
- Prometheus/Grafana/Alertmanager wired end-to-end, including a working
  alert path even without a real Slack workspace.
- Optional Wazuh decoder/rule assets for Vault audit events, with both a CI
  `wazuh-logtest` fixture gate and `make wazuh-live-test` to prove the live
  Vault audit file is tailed into the manager and produces an alert.
- A CI pipeline that gates on security *properties* (an integration test
  that asserts oracle status and scenario contracts), a live Terraform-plan
  OPA gate, not only lint.

## Try the demo

```bash
make demo-revoke              # one probe cycle; decision/reason evidence table
make chaos-sweep              # one-shot direct-OCSP latency experiment
make truststore-drift-demo    # installs a synthetic rogue CA and verifies detection
make wazuh-logtest            # evaluates the revoke audit fixture against rule 100101
```

## Verification workflow

Run the gates in this order from a clean checkout:

```bash
make bootstrap                # clean-stack bootstrap, PKI apply, ACME, AppRole, root-token revocation
make demo-revoke              # writes .data/last-cycle.json after the 180-second enforcement cycle
make test-integration         # validates the cycle report, live metrics, and signed trust-store drift
make truststore-drift-demo    # isolated rogue-root detection test
make up-full                  # adds Prometheus, Grafana, Alertmanager, truststore exporter
make test                     # Go unit tests with the race detector
make lint                     # Shell, Terraform, Go, and Dockerfile linters
make scan                     # Gitleaks and Trivy; both commands fail on findings
```

`make clean` removes containers, generated credentials, Vault recovery
material, local TLS keys, and Terraform state. The integration target consumes
the report produced by `make demo-revoke`, which keeps macOS and Linux results
consistent even though the macOS system curl lacks `--cert-status` support.

## Signed assurance evidence

Create a local demo keypair, then run a cycle. The key lives only under the
ignored `.data/attestation/` directory; it must be replaced with an external
KMS/HSM signer in production. `make env` also aligns the probe container's
non-root UID/GID with the invoking host user so bind-mounted evidence remains
readable and cleanable on Linux without weakening private-key permissions.

```bash
make attestation-key
make demo-revoke
```

When the key is mounted at `/run/attestation/` for the probe process,
`demo-revoke` writes `last-cycle.attestation.json` and verifies it using the
public key. A standalone process can produce the same envelope with
`probe run --attestation-key ... --attestation-out ...`; verify it with
`probe attest verify --public-key ... --input ...`. Each signed report binds
the canonical scenario digest and a canonical run-configuration digest; the
cycle evidence directory also retains the exact `scenario.json` bytes whose
SHA-256 is reported as `scenario_digest`.


### Live Wazuh ingestion check

After `make bootstrap`, start the Wazuh profile and exercise a real audited
Vault authentication failure:

```bash
make up-wazuh
make wazuh-live-test
```

The test requires Vault's file audit device to be active, verifies that the
audit file grows, and then waits for Wazuh rule `100103` in `alerts.json`.

## Assurance matrix

Status oracles start immediately after issuer acknowledgement. Each client
waits for the evidence boundary declared for it in the selected scenario
manifest; the client method is not the source of that scheduling decision.
OCSP/CRL publication boundaries fail closed: they open only after an enabled
status oracle actually observes validated `REJECT / REVOKED`, never merely
because its polling goroutine finished. The report separately records
OCSP-oracle publication, CRL publication, staple-source publication, staple
distribution, and client enforcement timing. Every result records its required
evidence and the timestamp at which each dependency was satisfied, so a verifier
can check that all boundaries preceded the first client attempt. A result
satisfies an explicit scenario contract; a TLS or network failure is
`INCONCLUSIVE`, not a successful rejection.

| Profile | Role | Method | `revoked_staple` contract |
|---|---|---|---|
| `openssl-ocsp-direct` | status oracle | direct OCSP | `REJECT / REVOKED` |
| `crl-check` | status oracle | full CRL | `REJECT / REVOKED` after CRL rebuild |
| `curl-cert-status` | client executor | stapled OCSP | `REJECT`; reason derived from libcurl evidence |
| `curl-default` | client executor | none | `ACCEPT / NO_REVOCATION_CHECK` |
| `go-tls-default` | client executor | none | `ACCEPT / NO_REVOCATION_CHECK` |
| `go-hardfail-ocsp` | client executor | custom stapled OCSP validation | `REJECT / REVOKED` |
| `python-requests` | client executor | none | `ACCEPT / NO_REVOCATION_CHECK` |

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
| Transit auto-unseal via a second persistent local Vault | seal Vault compromise unseals everything; loss of `.data/vault-seal` prevents recovery | AWS KMS / GCP KMS / Azure Key Vault / HSM; the seal service has no host-published API port |
| Vault listener `tls_disable = true` | plaintext on the Docker bridge | TLS on the listener with a bootstrap cert |
| Full CRL uses immediate rebuild (`auto_rebuild=false`) | expensive at high revocation volume; does not model periodic/delta CRL delivery | enable auto-rebuild/delta in production and model publication delay as an explicit assurance scenario |
| Recovery keys in `.data/vault-init.json` | plaintext key material on disk | PGP-encrypted shares distributed to separate key holders |
| `GRAFANA_ADMIN_PASSWORD` in `.env` | trivial credential | SSO/OIDC |
| ACME with no External Account Binding | any workload on the network can request a cert | `eab_policy: always-required` |
| Static non-expiring AppRole SecretIDs | credential remains usable until revoked | workload identity or automated response-wrapped SecretID rotation |
| Dev-mode seal Vault | compromise of the seal service reaches seal-Vault administration | KMS/HSM; the primary Vault already receives only an encrypt/decrypt-only transit token |

## Roadmap

1. Add unknown-status and expired-status OCSP response generators to the
   responder-only fault proxy.
2. Move local demo attestation signing to a KMS/HSM-backed signing service.
3. Add independently versioned client-image variants, then issuer adapters
   for OpenBao and step-ca after the assurance contracts are stable.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

## Acknowledgements

Built on HashiCorp Vault, Traefik, Prometheus, Grafana, and Wazuh.

## Research basis

- [`docs/benchmarks/ocsp-softfail-thresholds.md`](docs/benchmarks/ocsp-softfail-thresholds.md)
  separates the prior private-CA/`tc netem` client experiment from the current
  responder-scoped direct-oracle sweep and documents both sets of limitations.
- [`docs/benchmarks/trusted-ca-mitm.md`](docs/benchmarks/trusted-ca-mitm.md)
  documents the trusted-root interception result and trust-store control.
