# Threat Model

STRIDE analysis per plane. This complements `SECURITY.md`'s deliberate-deviation
table and the README's "Production notes" — read all three together.

## Issuance plane (Vault PKI, ACME, Traefik, demo-api)

| Threat | STRIDE | Mitigation in this repo |
|---|---|---|
| Attacker forges a request to Vault's root mount | Spoofing | AppRole auth scoped per service; `revocation-probe`'s policy explicitly denies `pki_root/*` (see Step 1.8 negative test) |
| Root CA private key exfiltrated | Tampering / Elevation | Root mount is only written to during initial Terraform apply; [rule 100102](../observability/wazuh/rules/local_rules.xml) alerts on any later write. Production fix: offline root on HSM (see README Production notes). |
| Vault audit log tampered with to hide a revocation | Repudiation | File audit device is append-only from Vault's perspective; ship to a separate log store (Wazuh) so the audit trail survives a compromised Vault container. |
| Attacker enumerates issued certs / secrets via Vault API | Information Disclosure | Least-privilege policies per service (`demo-api`, `revocation-probe`, `traefik-acme`), each scoped to only the paths it needs. |
| AppRole secret_id brute-forced | Denial of Service / Spoofing | [Rule 100104](../observability/wazuh/rules/local_rules.xml) alerts on 5+ auth failures in 60s from one source; `secret_id_ttl` bounds the exposure window. |
| Compromised AppRole token used to escalate to `sudo`-level Vault access | Elevation of Privilege | No policy in this repo grants `sudo`; verified explicitly in Step 1.8's negative test. |

## Assurance plane (revocation-probe, truststore-drift-agent)

| Threat | STRIDE | Mitigation in this repo |
|---|---|---|
| Attacker spoofs a "rejected" result to hide a real soft-fail | Spoofing / Tampering | Detection is measured by the harness itself dialing the canary endpoint, not by client self-report; pre-flight guard (Step 3.5) prevents false detections from being recorded. |
| Probe container compromised, used as a pivot (it has `NET_ADMIN`) | Elevation of Privilege | Capability scoped to this one container only; image scanned in CI; non-root user with `tc` granted via file capability rather than a root process. |
| Leaked `tc netem` qdisc silently corrupts unrelated latency measurements | Tampering (data integrity) | `chaos.Sweep` always clears the qdisc on return, including on SIGINT/SIGTERM (Step 3.7). |
| Attacker installs a rogue CA in a client's trust store (trusted-CA MITM) | Spoofing (undetectable at TLS layer by design) | Cannot be prevented by this repo; **detected** one layer down by `truststore-drift-agent`'s SPKI-hash diff against a signed baseline. See `docs/benchmarks/trusted-ca-mitm.md`. |

## Governance plane (Prometheus/Grafana/Alertmanager/Wazuh)

| Threat | STRIDE | Mitigation in this repo |
|---|---|---|
| Grafana admin credential guessed/leaked | Spoofing | `GRAFANA_ADMIN_PASSWORD` is demo-only (see Production notes); production fix is SSO/OIDC. |
| Alert fatigue causes a real soft-fail to be ignored | Repudiation (of the alert itself) | [ADR-0007](adr/0007-alerting-on-method-not-none-only.md): alerting excludes `method="none"` profiles, which are expected to accept every cycle. |
| Slack webhook URL leaked | Information Disclosure | Never inlined into `alertmanager.yml`; mounted from a gitignored file (`slack_api_url_file`). |
| Runbook link 404s during an actual incident | Availability (of the response process, not the system) | CI-checkable invariant: every `runbook_url` in `observability/prometheus/rules/*.yml` must resolve to a file that exists in the repo (Step 6.6). |

## Out of scope for this repo (v1)

- Kubernetes/Helm hardening (see [ADR-0005](adr/0005-compose-over-kubernetes.md); roadmap item).
- Windows client trust-store drift detection (roadmap item; `truststore-drift-agent`
  currently supports Debian/Ubuntu and RHEL paths, with macOS native paths
  documented but not implemented in the containerized demo path).
- Multi-region / disaster-recovery topology for Vault Raft storage.
