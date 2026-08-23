# PKI Sentinel Reuse Assessment for a Family Photo Cloud

Status: implementation assessment  
Scope: reusable assets in the current `pki-sentinel` repository only

## Executive conclusion

The repository can reduce work on deployment, service identity, observability,
security checks, failure testing, and operational documentation. It does not
contain reusable photo storage, resumable upload, mobile authentication, or iOS
application code.

The highest-value reuse is:

1. Docker Compose organization, health checks, initialization gates, and
   environment conventions.
2. GitHub Actions pipelines for linting, tests, secret scanning, vulnerability
   scanning, SBOM generation, image signing, and build provenance.
3. Prometheus, Grafana, and Alertmanager provisioning patterns.
4. The signed-baseline design in `truststore-drift-agent`, adapted into signed
   asset manifests for storage-integrity audits.
5. The `tc netem` chaos-test implementation, extended to verify interrupted and
   resumed uploads.
6. Vault AppRole, least-privilege policy, and audit patterns if Vault remains in
   the final deployment.
7. ADR, threat-model, runbook, and benchmark structures.

The PKI-specific services should not be treated as the photo-cloud backend.
They provide operational and security scaffolding, not the product data model or
upload protocol.

## Reuse matrix

| Existing component | Reuse level | Applicable use | Required adaptation |
|---|---|---|---|
| [`docker-compose.yml`](../docker-compose.yml) | High, structural | Single-host service orchestration, dependency gates, health checks, isolated network, persistent volumes, optional profiles | Replace the PKI application services with the photo API, uploader, database, workers, and storage mounts. Do not copy public port exposure unchanged. |
| [`.env.example`](../.env.example) | High, structural | Version pinning, configurable ports, local-only defaults, separation of committed configuration from secrets | Rename variables and remove all demo credentials. Keep real values in ignored files or a secret manager. |
| [`Makefile`](../Makefile) | High, structural | A small operator interface for bootstrap, start, stop, status, logs, test, scan, and cleanup | Replace PKI targets with photo-cloud lifecycle and backup/restore targets. Preserve idempotent targets and help text. |
| [`scripts/lib/wait_for.sh`](../scripts/lib/wait_for.sh) | Direct with a security change | Readiness polling in local bootstrap and CI | Remove the unconditional `curl -k` behavior for public TLS checks. Permit insecure verification only through an explicit local-test option. |
| [`docker-compose.observability.yml`](../docker-compose.observability.yml) | High, structural | Prometheus, Grafana, Alertmanager, node metrics, persistent state, and provisioned dashboards | Replace PKI scrape targets, alerts, and dashboards with upload, verification, queue, storage, backup, and authentication metrics. Bind administrative ports to the LAN or localhost. |
| [`observability/webhook-logger`](../observability/webhook-logger) | Direct for development | Local alert receiver when no external notification service is configured | Rename the image and keep it outside the production notification path. |
| [`docker-compose.wazuh.yml`](../docker-compose.wazuh.yml) | Optional | Central parsing and alerting for security audit events | Write new decoders and rules for login and asset events. The current Vault rules do not understand photo-cloud events. Wazuh is memory-heavy and should remain an optional profile. |
| [`services/demo-api`](../services/demo-api) | Medium, code patterns | Go service layout, graceful shutdown, `/healthz`, `/metrics`, Prometheus instrumentation, context cancellation, Vault client initialization | Retain infrastructure patterns only. Replace certificate lifecycle and demo handlers. Add stricter request limits, authentication middleware, storage logic, and separate readiness checks. |
| [`services/demo-api/internal/vaultauth`](../services/demo-api/internal/vaultauth) | Direct only when Vault is selected | Machine-to-machine AppRole login, token renewal, and reauthentication | Extract into a shared internal module. Add bounded exponential backoff and startup/readiness behavior suitable for the new services. Never use AppRole as family-user authentication. |
| [`services/truststore-drift-agent`](../services/truststore-drift-agent) | High, design pattern | Signed integrity manifests: sorted records, SHA-256 identifiers, Ed25519 signatures, verification before trusting a baseline | Replace CA records with asset records such as asset ID, owner ID, size, content SHA-256, storage key, and verification time. Use a canonical cross-language serialization format before signatures are verified by both Go and Swift. |
| [`services/revocation-probe`](../services/revocation-probe) | Low for product code; medium for probes | Periodic external checks, health/ready endpoints, metrics contracts, configuration profiles, and result reporting | Replace certificate-revocation scenarios with upload-path and storage-integrity probes. Do not retain Vault certificate issue/revoke logic. |
| [`services/revocation-probe/internal/chaos`](../services/revocation-probe/internal/chaos) | High for testing | Reproducible network impairment with guaranteed cleanup on cancellation or failure | Extend beyond delay to packet loss, rate limiting, connection resets, and service restarts. Run only in isolated test containers because it requires `NET_ADMIN`. |
| [`terraform/bootstrap`](../terraform/bootstrap) | Medium, conditional | Declarative Vault mounts, PKI roles, AppRoles, least-privilege policies, audit devices, and generated service credential files | Keep only if Vault is retained. Add roles and policies per photo-cloud service; do not share one broad role. The current Terraform bootstraps Vault resources, not the host, DNS, disks, firewall, or backup infrastructure. |
| [`config/traefik`](../config/traefik) | Medium, structural | HTTPS edge, Docker service discovery, JSON access logs, Prometheus metrics, health endpoint, and security-header middleware | Replace the private Vault ACME resolver with a public CA resolver for the iOS-facing endpoint. Disable the insecure dashboard, restrict admin endpoints, attach middleware explicitly, and replace `.internal` routes. |
| [`policy/opa`](../policy/opa) | Medium, framework | Policy-as-code gates with positive and negative fixtures in CI | Existing policies are certificate-specific. Add deployment policies for non-root containers, read-only mounts, approved images, bounded public ports, encryption requirements, and mandatory backup settings. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | High, structural | Matrix linting, race-enabled Go tests, Compose validation, integration environment startup, failure diagnostics, and artifact retention | Replace service matrices and add uploader, database migration, storage-integrity, and iOS build/test jobs. Keep failure logs free of credentials and personal image metadata. |
| [`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml) | High | Full-history Gitleaks, Trivy filesystem/image scans, Checkov, CodeQL, dependency review, and scheduled scans | Update service matrices and add Swift dependency scanning. Retain history scanning because credentials and personal metadata must not enter Git history. |
| [`.github/workflows/release.yml`](../.github/workflows/release.yml) | High for server images | Multi-architecture images, SBOMs, keyless Cosign signatures, attestations, and provenance | Change package names and service matrices. Add deployment verification that rejects unsigned or unexpected images. iOS release remains a separate App Store workflow. |
| [`docs/adr`](adr), [`docs/runbooks`](runbooks), [`docs/threat-model.md`](threat-model.md), and [`docs/benchmarks`](benchmarks) | High, structural | Durable decisions, incident response, threat analysis, test evidence, and reproducible measurements | Create photo-cloud-specific documents; do not rename PKI documents into a different meaning. Link shared operational conventions instead of duplicating them. |

## Recommended extraction order

### 1. Reuse immediately

- Copy the Compose layout conventions: pinned images, health checks,
  `service_healthy`/`service_completed_successfully` gates, optional profiles,
  read-only configuration mounts, and ignored runtime state.
- Copy the CI and release workflow structure, then replace all service matrices
  and image names.
- Copy the Prometheus/Grafana/Alertmanager provisioning layout and implement new
  metrics before adding dashboards.
- Copy the documentation structure: one architecture document, focused ADRs,
  incident runbooks, a STRIDE threat model, and benchmark data kept beside the
  method that produced it.

### 2. Extract after the upload service exists

- Generalize the signed-baseline functions from
  `services/truststore-drift-agent` into a signed asset-manifest tool.
- Generalize the `revocation-probe` health/metrics server into a synthetic upload
  probe that uploads a known fixture, downloads it, and confirms the expected
  SHA-256 value.
- Extend the `chaos` package and use it to prove resume behavior under packet
  loss, latency, process termination, and server restart.
- Add upload-integrity alerts and dashboards only after metric names and state
  transitions have become stable contracts.

### 3. Reuse only if the operational cost is justified

- Retain Vault for service secrets, internal certificate issuance, or internal
  mTLS only when it is already being operated and backed up.
- Retain Wazuh only when its audit correlation provides enough value for the
  available RAM and maintenance budget.
- Retain OPA when there are multiple deployment artifacts or contributors that
  benefit from automated policy gates.

## Integrity-specific reuse

The strongest direct connection to the photo-cloud integrity requirement is the
signed-baseline implementation in `truststore-drift-agent`.

Its reusable properties are:

- deterministic sorting before signing;
- SHA-256 identifiers for compared objects;
- Ed25519 signing and signature verification;
- refusal to trust a baseline with an invalid signature;
- explicit drift events and a non-zero exit status;
- append-style event output suitable for external collection.

An adapted asset manifest should contain at least:

```text
manifest_version
generated_at
asset_id
owner_id
storage_key
byte_size
content_sha256
verified_at
signature_key_id
signature
```

The content hash must still be calculated from the stored original. A signed
manifest proves that the recorded inventory was not silently modified; it does
not prove that an unverified upload was complete. Upload state, final hash
verification, durable file commit, and database visibility therefore remain the
responsibility of the new upload service.

The existing Vault audit device and Wazuh pipeline provide a second reusable
pattern: security events are written in structured form and shipped away from
the component being monitored. The new system still needs its own append-only
events for login, upload creation, interruption, resume, verification failure,
commit, deletion, and restore. Vault's audit log cannot replace this product
audit trail.

## Public TLS and identity boundaries

The current PKI stack is a private laboratory PKI. Its root CA, intermediate CA,
Vault ACME directory, `.internal` names, bootstrap certificate, and revocation
probe must not be used as the trust anchor for the public iOS API. The public
endpoint needs a certificate from a CA trusted by iOS without installing a
custom root.

Traefik remains reusable as the edge proxy after the following changes:

- configure a public ACME issuer;
- disable `api.insecure`;
- do not publish the dashboard, Prometheus, Grafana, Alertmanager, Vault, or
  database ports to the Internet;
- attach rate limiting, request-size, timeout, and security-header middleware;
- preserve JSON access logs while excluding credentials and photo metadata.

Vault AppRole is service authentication, not human authentication. Each family
member still requires a product account and session model. Asset ownership must
be derived from the authenticated user on the server and must never be accepted
from an arbitrary request field.

## Components that should not be copied unchanged

- `vault-seal` is a local stand-in for an external KMS and is not a production
  key-protection design.
- `VAULT_SEAL_TOKEN`, `GRAFANA_ADMIN_PASSWORD`, and other sample values are
  intentionally local defaults, not deployment secrets.
- Traefik's insecure dashboard and published administrative ports are unsuitable
  for an Internet-facing host.
- The private Vault CA is unsuitable for the iOS public API.
- Revocation, CRL, and OCSP logic does not provide file-upload integrity.
- Trust-store drift detection cannot run inside an ordinary iOS application;
  iOS does not expose the system trust store for this type of scan.
- Wazuh is not required for a small initial deployment and can consume more RAM
  than the application services.
- The current OPA rules enforce certificate policy only and offer no protection
  for uploads until new rules are written.
- `scripts/lib/wait_for.sh` currently disables TLS verification with `curl -k`;
  this behavior must not be used for production endpoint verification.

## Expected development savings

Reuse is concentrated in the server operations layer:

| Area | Expected reuse |
|---|---|
| Deployment and local lifecycle | High |
| CI, supply-chain security, and release | High |
| Metrics, dashboards, alerts, and operational docs | High |
| Service-to-service secrets and internal PKI | Medium and conditional |
| Network-failure and integrity test harnesses | Medium after adaptation |
| Photo data model and storage transactions | None |
| Resumable upload protocol | None |
| Family-user authentication and authorization | None |
| iOS app, Share Extension, and background upload | None |

This boundary prevents PKI-specific code from being forced into unrelated
product behavior. The repository can eliminate repeated infrastructure and
security boilerplate, while the photo-cloud implementation still needs a
separate upload protocol, asset catalog, authorization model, and iOS client.

## Minimal reuse backlog

1. Create a new repository or top-level application directory; do not mix photo
   assets or user data into `pki-sentinel` runtime state.
2. Port the Compose, `.env.example`, Makefile, and readiness conventions.
3. Port and rename the CI/security/release matrices.
4. Define photo-cloud Prometheus metrics and adapt the observability stack.
5. Build a synthetic upload probe and extend `netem` failure scenarios.
6. Extract the signed-baseline pattern into an asset-manifest verifier.
7. Decide whether Vault, Wazuh, and OPA provide enough value to enable them as
   optional profiles.
8. Write separate ADRs for public TLS, resumable upload, authentication, storage
   commit semantics, backup, and integrity verification.

