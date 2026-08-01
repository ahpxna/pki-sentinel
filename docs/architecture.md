# Architecture

pki-sentinel has three planes. The Assurance plane is the differentiator —
see [ADR-0004](adr/0004-assurance-plane-first-class.md).

| Plane | Responsibility |
|---|---|
| **Issuance** | Vault/OpenBao PKI (Root + Intermediate), ACME endpoint, Traefik edge, short-lived certs |
| **Assurance** | `revocation-probe` continuously issues a canary cert, revokes it, and measures whether each client profile actually rejects it. `truststore-drift-agent` detects unauthorized root CA installation. |
| **Governance** | Prometheus/Grafana/Alertmanager, Wazuh custom decoders for Vault audit logs, OPA policy gates in CI |

```mermaid
flowchart TB
  subgraph Issuance["Issuance plane"]
    direction TB
    RootCA["Vault: pki_root<br/>(Root CA, offline-style)"]
    IntCA["Vault: pki_int<br/>(Issuing CA, ACME, CRL/OCSP)"]
    Traefik["Traefik<br/>(ACME client, TLS edge)"]
    DemoAPI["demo-api<br/>(AppRole + KV + client cert)"]
    RootCA -->|signs| IntCA
    IntCA -->|ACME| Traefik
    IntCA -->|client cert| DemoAPI
  end

  subgraph Assurance["Assurance plane — the differentiator"]
    direction TB
    Probe["revocation-probe<br/>issue canary → revoke → poll 7 client profiles"]
    Drift["truststore-drift-agent<br/>SPKI hash diff vs signed baseline"]
    Probe -->|canary issue/revoke| IntCA
    Probe --> Metrics1["pki_revocation_* metrics"]
    Drift --> Metrics2["pki_truststore_unknown_roots"]
  end

  subgraph Governance["Governance plane"]
    direction TB
    Prom["Prometheus"]
    Grafana["Grafana dashboards"]
    Alertmanager["Alertmanager → Slack / webhook-logger"]
    Wazuh["Wazuh: Vault audit decoders + rules"]
    Metrics1 --> Prom
    Metrics2 --> Prom
    Prom --> Grafana
    Prom --> Alertmanager
    IntCA -->|file audit device| Wazuh
  end

  style Assurance fill:#2b3a4a,stroke:#e06c75,stroke-width:2px,color:#fff
```

See [`docs/diagrams/architecture.d2`](diagrams/architecture.d2) for the
regenerable source (`make diagrams`).

## ADR index

- [0001 — Vault vs step-ca](adr/0001-vault-vs-step-ca.md)
- [0002 — Auto-unseal trade-offs](adr/0002-auto-unseal-tradeoffs.md)
- [0003 — Short-lived certs over revocation](adr/0003-short-lived-certs-over-revocation.md)
- [0004 — Assurance plane as first-class](adr/0004-assurance-plane-first-class.md)
- [0005 — Compose over Kubernetes for v1](adr/0005-compose-over-kubernetes.md)
- [0006 — Alpine over distroless for the probe](adr/0006-alpine-over-distroless-for-probe.md)
- [0007 — Alerting on method != none only](adr/0007-alerting-on-method-not-none-only.md)
