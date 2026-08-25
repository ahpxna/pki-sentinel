# Threat Model

STRIDE analysis per plane. This complements `SECURITY.md`'s deliberate-deviation
table and the README's "Production notes" — read all three together.

## Issuance plane (Vault PKI, ACME, Traefik, demo-api)

| Threat | STRIDE | Mitigation in this repo |
|---|---|---|
| Attacker forges a request to Vault's root mount | Spoofing | AppRole auth scoped per service; `revocation-probe`'s policy explicitly denies `pki_root/*` (see Step 1.8 negative test) |
| Root CA private key exfiltrated | Tampering / Elevation | Root mount is only written during Terraform apply. An optional Wazuh rule is provided, but its end-to-end ingestion is not a verified control. Production fix: offline root on HSM (see README Production notes). |
| Vault audit log tampered with to hide a revocation | Repudiation | The file audit device records structured events. Production requires shipping them to a separately administered log store; the optional Wazuh assets in this repository do not yet prove that path end to end. |
| Attacker enumerates issued certs / secrets via Vault API | Information Disclosure | Least-privilege policies per service (`demo-api`, `revocation-probe`, `traefik-acme`), each scoped to only the paths it needs. |
| AppRole SecretID stolen | Spoofing | Policies are scoped per service. Static non-expiring SecretIDs are a Compose-demo limitation; production requires workload identity or response-wrapped rotation. |
| Compromised application AppRole token used to escalate | Elevation of Privilege | Application policies do not grant `sudo`. Terraform uses a separate bootstrap policy with `sudo` only on repository-owned mount/auth/audit administration paths. |
| Primary Vault process compromised and its transit credential exfiltrated | Elevation of Privilege | The primary receives an orphan periodic token restricted to `transit/encrypt/autounseal` and `transit/decrypt/autounseal`; the seal-Vault development root token is never mounted or injected into the primary. |

## Assurance plane (revocation-probe, truststore-drift-agent)

| Threat | STRIDE | Mitigation in this repo |
|---|---|---|
| Attacker spoofs a "rejected" result to hide a real soft-fail | Spoofing / Tampering | Decision and reason are separate; network/TLS failures are inconclusive; signed pre-revocation observations prove the BEFORE contract; each client waits only for its manifest-declared evidence boundary; command output hashes and environment fingerprints are retained in JSON. |
| Probe container compromised, used as a network pivot | Elevation of Privilege | Neither continuous probe nor one-shot chaos runner receives an added Linux capability. The fault proxy listens on loopback and forwards only the configured OCSP path. |
| Fault injection silently corrupts unrelated measurements | Tampering (data integrity) | Latency is applied inside a responder-only reverse proxy. Issuer API, CRL, and TLS target traffic bypass it; every sweep resets proxy delay to zero. |
| Attacker installs, removes, or replaces a root | Spoofing / Tampering | The exporter detects SPKI additions, removals, same-subject key changes, and expiry against a signed baseline. The demo signer key is not mounted into the exporter; production must keep it offline and pin the verification root. |

## Governance plane (Prometheus/Grafana/Alertmanager/Wazuh)

| Threat | STRIDE | Mitigation in this repo |
|---|---|---|
| Grafana admin credential guessed/leaked | Spoofing | `GRAFANA_ADMIN_PASSWORD` is demo-only (see Production notes); production fix is SSO/OIDC. |
| Alert fatigue causes a real soft-fail to be ignored | Repudiation (of the alert itself) | [ADR-0007](adr/0007-alerting-on-method-not-none-only.md): expected `NO_REVOCATION_CHECK` acceptance remains visible in the assurance matrix but does not page. |
| Slack webhook URL leaked | Information Disclosure | Never inlined into `alertmanager.yml`; mounted from a gitignored file (`slack_api_url_file`). |
| Runbook link 404s during an actual incident | Availability (of the response process, not the system) | CI-checkable invariant: every `runbook_url` in `observability/prometheus/rules/*.yml` must resolve to a file that exists in the repo (Step 6.6). |

## Out of scope for this repo (v1)

- Kubernetes/Helm hardening (see [ADR-0005](adr/0005-compose-over-kubernetes.md); roadmap item).
- Windows client trust-store drift detection (roadmap item; `truststore-drift-agent`
  currently supports Debian/Ubuntu and RHEL paths, with macOS native paths
  documented but not implemented in the containerized demo path).
- Multi-region / disaster-recovery topology for Vault Raft storage.
