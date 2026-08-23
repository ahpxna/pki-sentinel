# Security Policy

This is a demo/reference PKI platform. See `docs/threat-model.md` for the full STRIDE
analysis and the "Production notes" section of the README for deliberate demo shortcuts
and their production remediations.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security tab) rather than a public issue.

## Deliberate deviations from hardened defaults

| Container | Deviation | Reasoning |
|---|---|---|
| `revocation-probe` | Alpine, not distroless; ships `curl`, `openssl`, and `python3` | Client profiles are subprocess wrappers around real client tooling — see [ADR-0006](docs/adr/0006-alpine-over-distroless-for-probe.md). It runs as non-root and has no added container capability. |
| `chaos-runner` | Separate one-shot execution profile | The in-process reverse proxy accepts only the configured OCSP path and requires no Linux network capability. |
| `vault` | `tls_disable = true` on the listener | TLS is terminated by Traefik at the edge in this demo topology; plaintext exists only on the internal Docker bridge network. See the "Production notes" table below and [ADR-0002](docs/adr/0002-auto-unseal-tradeoffs.md). |
| `vault-seal` | Dev-mode Vault used as a transit auto-unseal key holder | A demo stand-in for a cloud KMS/HSM. See [ADR-0002](docs/adr/0002-auto-unseal-tradeoffs.md). |

See `docs/threat-model.md` for the full STRIDE analysis and the README's
"Production notes" section for the complete list of demo shortcuts and
their production remediations.
