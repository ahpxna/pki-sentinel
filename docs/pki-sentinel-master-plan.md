# pki-sentinel — Master Implementation Plan (Phase 0 → Phase 6)

> **Status: historical implementation plan.** This document preserves the
> original build sequence and is not an authoritative description of current
> behavior. Use [`README.md`](../README.md) and
> [`docs/architecture.md`](architecture.md) for implemented capabilities and
> current assurance semantics.

**Scope:** technical implementation plan for an environment with shell, file-write, and Docker access.
**Runtime:** Docker Compose only. Kubernetes is explicitly out of scope for this plan.
**Language of record:** all code, comments, commit messages, and documentation in English.

---

## 0. Global Contract — read before executing any phase

### 0.1 What this project is

`pki-sentinel` is a self-hosted internal PKI platform for small and medium enterprises with three planes:

| Plane | Responsibility |
|---|---|
| **Issuance** | Vault/OpenBao PKI (Root + Intermediate), ACME endpoint, Traefik edge, short-lived certs |
| **Assurance** | `revocation-probe` continuously issues a canary cert, revokes it, and measures whether each client profile actually rejects it. `truststore-drift-agent` detects unauthorized root CA installation. |
| **Governance** | Prometheus/Grafana/Alertmanager, Wazuh custom decoders for Vault audit logs, OPA policy gates in CI |

The Assurance plane is the differentiator. If a trade-off ever forces a cut, cut Issuance polish, never Assurance.

### 0.2 Non-negotiable implementation rules

1. **Idempotency.** Every script must be safe to run twice. Use `vault status || true`, `terraform apply -auto-approve` guarded by state, `mkdir -p`, `docker compose up -d` (never `docker compose run` for long-lived services).
2. **Pin every version.** No `:latest` tags anywhere. No unpinned GitHub Action (`uses: actions/checkout@v4` is acceptable; `@main` is not).
3. **No `sleep N` as a synchronization primitive.** Always poll a health endpoint in a bounded loop with a timeout and a clear failure message. A helper `scripts/lib/wait_for.sh` must exist by end of Phase 0 and be reused everywhere.
4. **Never commit secrets.** `.env` is gitignored; `.env.example` is committed with placeholder values only. Any generated key material lands in `./.data/` which is gitignored.
5. **Stop at each Verification gate.** If a milestone command fails, fix it before proceeding. Do not begin the next step with a red gate.
6. **Commit per step.** Conventional Commits format: `feat(phase1): create intermediate CA via terraform`. One commit per numbered step.
7. **Do not invent CLI flags.** If a flag or API path is uncertain, run `--help` or query the container's own OpenAPI/docs endpoint before writing it into a script.
8. **All host ports are configurable via `.env`** so the stack does not collide with a developer's existing services.

### 0.3 Pinned versions (single source of truth — put these in `.env.example`)

```
VAULT_IMAGE=hashicorp/vault:1.21.4
# Apache-2.0 alternative, drop-in: openbao/openbao:2.0.0
TRAEFIK_IMAGE=traefik:v3.7.9
PROMETHEUS_IMAGE=prom/prometheus:v2.53.1
GRAFANA_IMAGE=grafana/grafana:11.1.3
ALERTMANAGER_IMAGE=prom/alertmanager:v0.27.0
NODE_EXPORTER_IMAGE=prom/node-exporter:v1.8.2
GO_VERSION=1.26.7
TERRAFORM_VERSION=1.9.5
TERRAFORM_VAULT_PROVIDER=~> 4.3
WAZUH_VERSION=4.8.2
```

### 0.4 Naming and network conventions

- Docker network: `pki-sentinel` (external: false, driver bridge).
- Internal DNS domain for issued certs: `*.internal`.
- Service hostnames = compose service names: `vault`, `vault-seal`, `traefik`, `demo-api`, `revocation-probe`, `prometheus`, `grafana`, `alertmanager`.
- Vault mounts: `pki_root`, `pki_int`, `kv` (kv-v2), `transit` (on `vault-seal` only).
- All Go modules: `github.com/ahpxna/pki-sentinel/services/<name>`.

### 0.5 Directory structure (create the full skeleton in Phase 0, populate later)

```
pki-sentinel/
├── README.md  SECURITY.md  CONTRIBUTING.md  LICENSE  Makefile
├── .env.example  .gitignore  .dockerignore  .editorconfig
├── docker-compose.yml
├── docker-compose.observability.yml
├── docker-compose.wazuh.yml
├── docs/
│   ├── architecture.md  threat-model.md
│   ├── adr/  runbooks/  benchmarks/  images/
├── terraform/
│   ├── bootstrap/{main.tf,variables.tf,outputs.tf,versions.tf,policies.tf,roles.tf}
│   └── modules/{pki-hierarchy,app-identity}/
├── ansible/                       # Phase 6 stretch, skeleton only
├── services/
│   ├── revocation-probe/
│   ├── truststore-drift-agent/
│   └── demo-api/
├── observability/
│   ├── prometheus/{prometheus.yml,rules/}
│   ├── grafana/provisioning/{datasources,dashboards}/
│   ├── grafana/dashboards/
│   ├── alertmanager/config.yml
│   └── wazuh/{decoders,rules}/
├── policy/opa/
├── tests/{integration,e2e}/
├── scripts/{lib/,bootstrap.sh,demo-revoke.sh,teardown.sh}
└── .github/workflows/
```

---

# PHASE 0 — Scaffold

**Goal:** `make up` starts a Vault dev-mode container and `make status` reports healthy. Nothing more.
**Estimated effort:** 1 day.

### Step 0.1 — Initialize repository skeleton

**Target files:** `.gitignore`, `.dockerignore`, `.editorconfig`, `LICENSE`, `README.md` (stub), `CONTRIBUTING.md` (stub), `SECURITY.md` (stub), plus all empty directories from §0.5 with a `.gitkeep` in each otherwise-empty one.

**Action:**
- `git init`, default branch `main`.
- `LICENSE` = Apache-2.0 full text.
- `.gitignore` must include at minimum:
  ```
  .env
  .data/
  *.pem
  *.key
  *.crt
  !docs/**/*.crt
  terraform/**/.terraform/
  terraform/**/*.tfstate*
  terraform/**/.terraform.lock.hcl
  services/**/bin/
  .DS_Store
  ```
  Note: `.terraform.lock.hcl` is normally committed, but in Phase 0 there is no provider yet. Phase 1 Step 1.2 will remove that ignore line and commit the lock file.
- `README.md` stub: title, one-liner, `## Status: under construction`, link to `docs/architecture.md`.

**Verification:** `git status --porcelain` shows only intended files; `test -d docs/adr && test -d services/revocation-probe && echo OK`.

---

### Step 0.2 — Shell helper library

**Target file:** `scripts/lib/wait_for.sh`

**Action:** Implement three reusable functions, `set -euo pipefail` at the top, safe to `source` multiple times.

```bash
#!/usr/bin/env bash
# Usage: wait_for_http <url> <timeout_seconds> [expected_http_codes_regex]
wait_for_http() {
  local url="$1" timeout="${2:-60}" ok="${3:-^(2|3)[0-9][0-9]$}"
  local start; start=$(date +%s)
  while true; do
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' -k --max-time 3 "$url" || echo 000)
    [[ "$code" =~ $ok ]] && { echo "[wait_for] $url ready (HTTP $code)"; return 0; }
    (( $(date +%s) - start > timeout )) && { echo "[wait_for] TIMEOUT after ${timeout}s waiting for $url (last=$code)" >&2; return 1; }
    sleep 1
  done
}

# Usage: wait_for_cmd <timeout_seconds> <command...>
wait_for_cmd() { local timeout="$1"; shift; local start; start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    (( $(date +%s) - start > timeout )) && { echo "[wait_for] TIMEOUT running: $*" >&2; return 1; }
    sleep 1
  done; return 0; }

require_bin() { for b in "$@"; do command -v "$b" >/dev/null || { echo "Missing required binary: $b" >&2; return 1; }; done; }
```

**Verification:** `bash -n scripts/lib/wait_for.sh && source scripts/lib/wait_for.sh && wait_for_cmd 5 true && echo OK`

---

### Step 0.3 — `.env.example` and env loading

**Target files:** `.env.example`

**Action:** Include the version pins from §0.3 plus:
```
COMPOSE_PROJECT_NAME=pki-sentinel
VAULT_PORT=8200
VAULT_SEAL_PORT=8210
TRAEFIK_HTTP_PORT=8080
TRAEFIK_HTTPS_PORT=8443
TRAEFIK_DASHBOARD_PORT=8081
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
ALERTMANAGER_PORT=9093
PROBE_METRICS_PORT=9110
GRAFANA_ADMIN_PASSWORD=changeme-local-only
SLACK_WEBHOOK_URL=
PKI_DOMAIN=internal
ORG_NAME=PKI Sentinel Demo
# Phase 0 only. Removed in Phase 1.
VAULT_DEV_ROOT_TOKEN_ID=root-dev-token
```

**Verification:** `cp .env.example .env && set -a && . ./.env && set +a && echo "$VAULT_IMAGE"` prints the pinned image.

---

### Step 0.4 — Minimal `docker-compose.yml` (Vault dev mode)

**Target file:** `docker-compose.yml`

**Action:**
```yaml
name: ${COMPOSE_PROJECT_NAME:-pki-sentinel}

networks:
  pki-sentinel:
    driver: bridge

services:
  vault:
    image: ${VAULT_IMAGE}
    container_name: pki-vault
    cap_add: ["IPC_LOCK"]
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: ${VAULT_DEV_ROOT_TOKEN_ID}
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
      VAULT_ADDR: http://127.0.0.1:8200
    ports: ["${VAULT_PORT}:8200"]
    networks: [pki-sentinel]
    healthcheck:
      test: ["CMD", "vault", "status"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 5s
```

Do **not** add volumes yet — dev mode is in-memory by design and this is thrown away in Phase 1.

**Verification:** `docker compose up -d && docker compose ps` shows `pki-vault` as `healthy`; `curl -s localhost:8200/v1/sys/health | jq .initialized` returns `true`.

---

### Step 0.5 — Makefile

**Target file:** `Makefile`

**Action:** Tab-indented recipes, `.PHONY` on every target, self-documenting `help` as the default goal.

Required targets for Phase 0 (later phases append targets without replacing existing Makefile content):

| Target | Behaviour |
|---|---|
| `help` | default; greps `##` comments and prints aligned list |
| `env` | `test -f .env \|\| cp .env.example .env` |
| `up` | `env` then `docker compose up -d` then `make status` |
| `down` | `docker compose down` |
| `clean` | `docker compose down -v && rm -rf .data` |
| `status` | `docker compose ps` + a `wait_for_http` on Vault health |
| `logs` | `docker compose logs -f --tail=100` |
| `lint` | placeholder that exits 0 in Phase 0 |

Pattern for self-documenting help:
```make
.DEFAULT_GOAL := help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n",$$1,$$2}'
```

**Verification / Milestone (Phase 0 gate):**
```bash
make clean && make up && make status
curl -s localhost:8200/v1/sys/health | jq -e '.sealed == false'
```
Both must succeed. Commit: `feat(phase0): scaffold repo, makefile, vault dev compose`.

---

# PHASE 1 — PKI hierarchy via Terraform

**Goal:** Production-shaped Vault (Raft storage + transit auto-unseal), Root CA and Intermediate CA fully declared in Terraform, AIA/CRL/OCSP endpoints correct, root token revoked at the end of bootstrap.
**Estimated effort:** 3–4 days.

### Step 1.1 — Replace dev mode with Raft + transit auto-unseal

**Target files:** `docker-compose.yml` (modify), `config/vault/vault.hcl` (new), `config/vault-seal/vault-seal.hcl` (new)

**Action:**

Add a second Vault instance `vault-seal` that exists solely to hold a `transit` key used to auto-unseal the primary. Run `vault-seal` in dev mode (acceptable and documented — see ADR-0002; in production this is a cloud KMS).

`config/vault/vault.hcl`:
```hcl
ui = true
disable_mlock = true

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # TLS terminated by Traefik in Phase 2; documented in threat-model.md
}

seal "transit" {
  address         = "http://vault-seal:8200"
  disable_renewal = "false"
  key_name        = "autounseal"
  mount_path      = "transit/"
  tls_skip_verify = "true"
}

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"
```

Compose changes for `vault`:
- Remove all `VAULT_DEV_*` env vars.
- `command: server -config=/vault/config/vault.hcl`
- `environment: VAULT_TOKEN` is **not** set here; scripts export it.
- `environment: VAULT_SEAL_TOKEN` passed via `.env` (the development token of `vault-seal`) and mapped to the authentication variable used by the transit seal client. Vault does not interpolate `token = "${VAULT_SEAL_TOKEN}"` in `vault.hcl`; supported options are a templated seal stanza or the `VAULT_TOKEN` environment variable. The selected mechanism must be verified with `vault server -help` and container logs, then recorded in `docs/adr/0002-auto-unseal-tradeoffs.md`.
- Volumes: `./config/vault:/vault/config:ro`, `./.data/vault:/vault/data`
- `depends_on: vault-seal: {condition: service_healthy}`
- Healthcheck must tolerate the "sealed/uninitialized" states before bootstrap:
  `test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8200/v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204 || exit 1"]`

`vault-seal` service: dev mode, `VAULT_DEV_ROOT_TOKEN_ID: ${VAULT_SEAL_TOKEN}`, port `${VAULT_SEAL_PORT}:8200`.

**Verification:**
```bash
make clean && make up
docker compose logs vault | grep -i "core: security barrier not initialized"   # expected pre-bootstrap
curl -s localhost:8200/v1/sys/health | jq '.initialized, .sealed'             # false, true
```

---

### Step 1.2 — Bootstrap script: init, auto-unseal check, token handoff

**Target file:** `scripts/bootstrap.sh`

**Action:** The script must:
1. `source scripts/lib/wait_for.sh`; `require_bin docker curl jq terraform`.
2. Wait for `vault-seal` transit engine: enable `transit` and create key `autounseal` if absent (idempotent: `vault secrets enable transit || true`, `vault write -f transit/keys/autounseal || true`).
3. Restart `vault` so it can reach the transit key, then `wait_for_http` on `sys/health` accepting `501` (uninitialized).
4. If `.data/vault-init.json` does **not** exist: run `vault operator init -recovery-shares=3 -recovery-threshold=2 -format=json` inside the container, write output to `.data/vault-init.json` with `chmod 600`. (With auto-unseal these are *recovery* keys, not unseal keys — say so in the log output.)
5. Extract `root_token`, export `VAULT_TOKEN`.
6. Assert `sealed == false` without any manual unseal step. If it is still sealed, fail loudly — auto-unseal is broken.
7. Create a Terraform-scoped token: `vault token create -policy=root -period=60m -format=json` and write it to `.data/tf-token` (600). Terraform will consume this, not the root token.
8. Print next-step instructions.

**Verification:**
```bash
./scripts/bootstrap.sh
jq -e '.root_token != null' .data/vault-init.json
curl -s localhost:8200/v1/sys/health | jq -e '.sealed == false'
```

---

### Step 1.3 — Terraform provider skeleton

**Target files:** `terraform/bootstrap/versions.tf`, `variables.tf`, `providers.tf`, `terraform.tfvars.example`

**Action:**
```hcl
# versions.tf
terraform {
  required_version = ">= 1.9.0"
  required_providers {
    vault = { source = "hashicorp/vault", version = "~> 4.3" }
    tls   = { source = "hashicorp/tls",   version = "~> 4.0" }
  }
}
```
`providers.tf` reads `VAULT_ADDR` and `VAULT_TOKEN` from environment — do not hardcode tokens in `.tf` files.

Variables: `pki_domain` (default `internal`), `org_name`, `vault_public_addr` (default `http://localhost:8200`, used to construct AIA/CRL/OCSP URLs), `root_ttl_hours` (default `87600`), `int_ttl_hours` (default `8760`), `leaf_max_ttl_hours` (default `24`).

Remove `terraform/**/.terraform.lock.hcl` from `.gitignore` and commit the lock file.

**Verification:** `cd terraform/bootstrap && terraform init && terraform validate`

---

### Step 1.4 — Root CA

**Target file:** `terraform/bootstrap/pki_root.tf`

**Action:**
```hcl
resource "vault_mount" "pki_root" {
  path                      = "pki_root"
  type                      = "pki"
  max_lease_ttl_seconds     = var.root_ttl_hours * 3600
  description               = "Offline-style Root CA. Signs the intermediate only."
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend              = vault_mount.pki_root.path
  type                 = "internal"
  common_name          = "${var.org_name} Root CA R1"
  ttl                  = "${var.root_ttl_hours}h"
  key_type             = "ec"
  key_bits             = 384
  exclude_cn_from_sans = true
  organization         = var.org_name
  ou                   = "PKI Sentinel"
}
```
Also `vault_pki_secret_backend_config_urls` for the root pointing at its own CRL/issuing endpoints.

**Verification:**
```bash
terraform apply -auto-approve
curl -s localhost:8200/v1/pki_root/ca/pem | openssl x509 -noout -subject -dates -text | grep -E "CA:TRUE|Subject:"
```
Must show `CA:TRUE`, `pathlen` unset or ≥1, and a ~10-year validity.

---

### Step 1.5 — Intermediate CA (CSR → sign → set-signed chain)

**Target file:** `terraform/bootstrap/pki_int.tf`

**Action:** Three chained resources in this exact order:
1. `vault_mount "pki_int"` (`max_lease_ttl_seconds = var.int_ttl_hours * 3600`).
2. `vault_pki_secret_backend_intermediate_cert_request` (`type = "internal"`, `common_name = "${var.org_name} Issuing CA I1"`, EC P-256).
3. `vault_pki_secret_backend_root_sign_intermediate` — backend `pki_root`, `csr = ...csr`, `ttl = "${var.int_ttl_hours}h"`, `format = "pem_bundle"`.
4. `vault_pki_secret_backend_intermediate_set_signed` — `certificate = join("\n", [signed.certificate, root.certificate])`.

**Verification:**
```bash
curl -s localhost:8200/v1/pki_int/ca_chain > /tmp/chain.pem
openssl crl2pkcs7 -nocrl -certfile /tmp/chain.pem | openssl pkcs7 -print_certs -noout
# must list exactly 2 certificates: Issuing CA I1 then Root CA R1
openssl verify -CAfile <(curl -s localhost:8200/v1/pki_root/ca/pem) \
  <(curl -s localhost:8200/v1/pki_int/ca/pem)   # → OK
```

---

### Step 1.6 — AIA, CRL distribution points, OCSP responder

**Target file:** `terraform/bootstrap/pki_int_config.tf`

**Action:**
```hcl
resource "vault_pki_secret_backend_config_urls" "int" {
  backend                 = vault_mount.pki_int.path
  issuing_certificates    = ["${var.vault_public_addr}/v1/pki_int/ca"]
  crl_distribution_points = ["${var.vault_public_addr}/v1/pki_int/crl"]
  ocsp_servers            = ["${var.vault_public_addr}/v1/pki_int/ocsp"]
}
```
Plus CRL/OCSP behaviour via `vault_generic_endpoint` on `pki_int/config/crl`:
```json
{ "expiry": "72h", "disable": false, "ocsp_disable": false, "ocsp_expiry": "1h",
  "auto_rebuild": false, "enable_delta": false }
```
The assurance baseline consumes Vault's full `/crl` endpoint and expects a successful revocation to become visible immediately, so `auto_rebuild` and delta CRLs are disabled here. Production PKI scenarios should model periodic/delta CRL publication separately, where publication cadence is an explicit assurance variable. Keep `ocsp_expiry=1h` deliberate as another benchmark knob.

Configure the cluster path (required for AIA and ACME to emit correct URLs):
`vault write pki_int/config/cluster path="${var.vault_public_addr}/v1/pki_int" aia_path="${var.vault_public_addr}/v1/pki_int"`.

**Verification:**
```bash
# after issuing a test cert in Step 1.7
openssl x509 -in /tmp/leaf.pem -noout -text | grep -A2 "Authority Information Access"
# must contain OCSP - URI:.../v1/pki_int/ocsp  and CA Issuers - URI:.../v1/pki_int/ca
openssl x509 -in /tmp/leaf.pem -noout -text | grep -A1 "X509v3 CRL Distribution Points"
```

---

### Step 1.7 — Issuing roles

**Target file:** `terraform/bootstrap/roles.tf`

**Action:** Create three roles:
- `server` — `allowed_domains = [var.pki_domain]`, `allow_subdomains = true`, `max_ttl = 24h`, `ttl = 24h`, `key_type = ec`, `key_bits = 256`, `allow_ip_sans = true`, `no_store = false`.
- `client` — `client_flag = true`, `server_flag = false`, `allowed_domains` same, used for mTLS in Phase 2.
- `canary` — used exclusively by `revocation-probe`. `ttl = 10m`, `max_ttl = 30m`, `allowed_domains = ["canary.${var.pki_domain}"]`, `allow_subdomains = true`. Short TTL so revoked canaries expire out of the CRL quickly and the CRL does not grow unbounded.

**Verification:**
```bash
vault write -format=json pki_int/issue/server common_name=test.internal ttl=1h > /tmp/leaf.json
jq -r .data.certificate /tmp/leaf.json > /tmp/leaf.pem
openssl verify -CAfile /tmp/chain.pem /tmp/leaf.pem   # → OK
```

---

### Step 1.8 — Policies, AppRole auth, KV-v2

**Target files:** `terraform/bootstrap/policies.tf`, `terraform/bootstrap/auth.tf`, `terraform/bootstrap/policies/*.hcl`

**Action:**
- Enable `kv` (v2) mount and seed `kv/demo-api/config` with a fake DB password (from a Terraform `random_password`, not hardcoded).
- Policies (least privilege, one file each):
  - `demo-api`: `read` on `kv/data/demo-api/*`, `update` on `pki_int/issue/client`.
  - `revocation-probe`: `update` on `pki_int/issue/canary`, `update` on `pki_int/revoke`, `read` on `pki_int/cert/*`, `read` on `pki_int/crl` — **no** access to `pki_root`, **no** `sudo`.
  - `traefik-acme`: read on the ACME directory paths only.
- `vault_auth_backend "approle"` + one `vault_approle_auth_backend_role` per service, `token_ttl = 1h`, `token_max_ttl = 4h`, `secret_id_ttl = 24h`.
- Write role-id/secret-id for each service to `.data/approle/<service>.env` via a `local_file` resource or a post-apply script. Gitignored.

**Verification:**
```bash
# negative test — the probe must NOT be able to touch the root CA
VAULT_TOKEN=$(probe-login) vault read pki_root/cert/ca && echo "FAIL: over-privileged" || echo "OK: denied"
```

---

### Step 1.9 — Revoke the root token

**Target file:** `scripts/bootstrap.sh` (append)

**Action:** After `terraform apply` succeeds, run `vault token revoke -self` using the root token, and print:
> Root token revoked. Recovery keys are in `.data/vault-init.json`. To regain root access run `vault operator generate-root`. See `docs/runbooks/vault-seal-recovery.md`.

Guard it behind `PKI_SENTINEL_KEEP_ROOT=1` for local iteration, defaulting to revoke.

**Verification / Milestone (Phase 1 gate):**
```bash
make clean && make up && ./scripts/bootstrap.sh && make tf-apply
# full chain works
openssl verify -CAfile <(curl -s localhost:8200/v1/pki_int/ca_chain) /tmp/leaf.pem
# root token is dead
VAULT_TOKEN=$(jq -r .root_token .data/vault-init.json) vault token lookup && echo FAIL || echo OK
```
Write `docs/adr/0001-vault-vs-step-ca.md` and `docs/adr/0002-auto-unseal-tradeoffs.md` now, while the reasoning is fresh. Commit.

---

# PHASE 2 — ACME + Traefik + demo-api

**Goal:** Traefik obtains a certificate from Vault's ACME endpoint with zero manual steps; `demo-api` authenticates via AppRole, pulls a secret from KV-v2, and serves mTLS.
**Estimated effort:** 3–4 days.

### Step 2.1 — Enable ACME on `pki_int`

**Target file:** `terraform/bootstrap/acme.tf`

**Action:** Vault's ACME server requires three things, all of which must be present or ACME returns 404:
1. Mount tune on `pki_int`:
   - `allowed_response_headers = ["Last-Modified", "Location", "Replay-Nonce", "Link"]`
   - `passthrough_request_headers = ["If-Modified-Since"]`
2. `pki_int/config/cluster` with `path` and `aia_path` set (done in Step 1.6 — verify it is non-empty).
3. `pki_int/config/acme` with `{"enabled": true, "allowed_roles": ["server"], "default_directory_policy": "role:server", "allowed_issuers": ["*"], "eab_policy": "not-required"}`.

The `sys/mounts/pki_int/tune` endpoint may also require `passthrough_request_headers`; verify by requesting the directory endpoint before proceeding.

**Verification:**
```bash
curl -s localhost:8200/v1/pki_int/acme/directory | jq -e '.newNonce and .newAccount and .newOrder'
```
This must return the ACME directory JSON. If it 404s, ACME is not correctly enabled — do not proceed.

---

### Step 2.2 — Traefik service with internal ACME resolver

**Target files:** `docker-compose.yml` (add service), `config/traefik/traefik.yml`, `config/traefik/dynamic/tls.yml`

**Action:**
`config/traefik/traefik.yml` (static):
```yaml
entryPoints:
  web:       { address: ":80", http: { redirections: { entryPoint: { to: websecure, scheme: https } } } }
  websecure: { address: ":443" }
  traefik:   { address: ":8080" }

providers:
  docker: { exposedByDefault: false, network: pki-sentinel }
  file:   { directory: /etc/traefik/dynamic, watch: true }

certificatesResolvers:
  internal:
    acme:
      caServer: http://vault:8200/v1/pki_int/acme/directory
      email: pki-sentinel@example.invalid
      storage: /acme/acme.json
      tlsChallenge: {}

api: { dashboard: true, insecure: true }
metrics:
  prometheus: { addEntryPointsLabels: true, addServicesLabels: true }
accessLog: { format: json, filePath: /var/log/traefik/access.log }
log: { level: INFO, format: json }
```

Two required configuration details:
- Because `caServer` uses plain HTTP inside the Docker network, no CA trust bundle is needed for the ACME transport. A future switch to HTTPS requires mounting the root CA into the Traefik container and setting `LEGO_CA_CERTIFICATES=/certs/root.pem`.
- Vault ACME requires the `tls-alpn-01` or `http-01` challenge hostname to resolve. Inside Compose, hostnames such as `api.internal` need an `extra_hosts` entry or network alias so `vault` can reach port 443. Add the `api.internal` and `probe.internal` network aliases to Traefik and verify with `docker compose exec vault getent hosts api.internal`.

**Verification:**
```bash
docker compose up -d traefik
docker compose logs traefik | grep -i "certificate obtained\|acme"
docker compose exec traefik cat /acme/acme.json | jq -e '.internal.Certificates | length > 0'
echo | openssl s_client -connect localhost:${TRAEFIK_HTTPS_PORT} -servername api.internal 2>/dev/null \
  | openssl x509 -noout -issuer   # must show "Issuing CA I1"
```

---

### Step 2.3 — `demo-api` service (Go)

**Target files:** `services/demo-api/{go.mod,main.go,internal/vaultauth/vaultauth.go,Dockerfile}`

**Action:** A small HTTP service that demonstrates the full identity loop:
1. On boot, read `VAULT_ROLE_ID` / `VAULT_SECRET_ID` from env (mounted from `.data/approle/demo-api.env`).
2. Login via AppRole → get token → start a renewer goroutine.
3. Read `kv/data/demo-api/config` → log only the *presence* of the secret, never its value.
4. Request a client cert from `pki_int/issue/client` with 24h TTL; schedule renewal at 2/3 of TTL.
5. Expose:
   - `GET /healthz` → `200 {"status":"ok"}`
   - `GET /whoami` → returns the CN and NotAfter of its own current cert
   - `GET /metrics` → Prometheus (cert expiry gauge, vault token TTL gauge, renewal counter)
6. Dockerfile: multi-stage, `golang:${GO_VERSION}-alpine` builder → `gcr.io/distroless/static-debian12:nonroot` runtime, `USER nonroot`, `CGO_ENABLED=0`, `-ldflags="-s -w"`, and a `HEALTHCHECK` is not possible in distroless — use a Compose-level healthcheck against Traefik instead.

Compose labels:
```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.demo-api.rule=Host(`api.internal`)
  - traefik.http.routers.demo-api.entrypoints=websecure
  - traefik.http.routers.demo-api.tls.certresolver=internal
  - traefik.http.services.demo-api.loadbalancer.server.port=8000
```

**Verification:**
```bash
curl --cacert <(curl -s localhost:8200/v1/pki_int/ca_chain) \
     --resolve api.internal:${TRAEFIK_HTTPS_PORT}:127.0.0.1 \
     https://api.internal:${TRAEFIK_HTTPS_PORT}/whoami | jq .
docker compose logs demo-api | grep -c "secret loaded"      # ≥1, and no secret value in logs
docker compose logs demo-api | grep -i "password\|s3cr" && echo "FAIL: secret leaked to logs" || echo OK
```

---

### Step 2.4 — Makefile additions

**Target file:** `Makefile` (append)

Targets: `tf-init`, `tf-apply`, `tf-destroy`, `bootstrap` (= `up` + `bootstrap.sh` + `tf-apply`), `demo-api-logs`, `ca-chain` (writes `.data/ca_chain.pem` for host-side curl).

**Verification / Milestone (Phase 2 gate):**
```bash
make clean && make bootstrap
make ca-chain
curl --cacert .data/ca_chain.pem --resolve api.internal:8443:127.0.0.1 https://api.internal:8443/healthz
```
One command from zero to a working internally-trusted HTTPS service. Commit.

---

# PHASE 3 — `revocation-probe` (the core assurance service)

**Goal:** A Go service that, on a schedule, issues a canary certificate, revokes it, and measures per-client-profile detection time and soft-fail rate, exporting everything to Prometheus.
**Estimated effort:** 1–1.5 weeks. This is the most important phase. Budget accordingly.

### Step 3.1 — Module skeleton and domain model

**Target files:** `services/revocation-probe/{go.mod,cmd/probe/main.go}`, `internal/{issuer,canary,profiles,runner,metrics,config}/`

**Action:** Define the core types first, before any I/O code.

```go
// internal/profiles/profile.go
type Outcome string
const (
    OutcomeRejected Outcome = "rejected"   // client correctly refused the revoked cert
    OutcomeAccepted Outcome = "accepted"   // soft-fail: client used a revoked cert
    OutcomeError    Outcome = "error"      // harness failure, not a security signal
)

type CheckMethod string
const (
    MethodOCSPDirect  CheckMethod = "ocsp_direct"   // query the responder, no TLS
    MethodOCSPStapled CheckMethod = "ocsp_stapled"  // must-staple / stapled response
    MethodCRL         CheckMethod = "crl"
    MethodNone        CheckMethod = "none"          // client performs no revocation check
)

type Profile struct {
    Name        string
    Method      CheckMethod
    Description string
    // Probe returns whether the client rejected the connection.
    Probe func(ctx context.Context, target Target) (Outcome, error)
}

type Result struct {
    Profile      string
    Outcome      Outcome
    RevokedAt    time.Time
    DetectedAt   time.Time
    DetectionDur time.Duration
    Attempts     int
    Err          string
}
```

**Verification:** `cd services/revocation-probe && go build ./... && go vet ./...`

---

### Step 3.2 — Vault issuer client

**Target file:** `internal/issuer/vault.go`

**Action:** Methods: `Login()` (AppRole, with token renewal), `IssueCanary(cn string) (*CanaryCert, error)` returning cert PEM, key PEM, chain, and `serial_number`; `Revoke(serial string) (revokedAt time.Time, err error)`; `FetchCRL()`; `QueryOCSP(cert, issuer) (ocsp.ResponseStatus, error)` using `golang.org/x/crypto/ocsp`.

Critical: `RevokedAt` must be captured from the **client side immediately before** the revoke API call returns, and the code must record both `t_request` and `t_response`. Use `t_response` as `RevokedAt` — this is the earliest instant the revocation is guaranteed durable. Document this choice in a comment; it is the same measurement discipline as the CYB 260 methodology, where detection time was defined relative to the CA-side revocation timestamp.

**Verification:** unit test with a live Vault via `make up`:
```bash
go test ./internal/issuer/... -run TestIssueRevoke -v
```

---

### Step 3.3 — Ephemeral TLS target

**Target file:** `internal/canary/server.go`

**Action:** For each cycle, start an in-process `net/http` TLS server bound to a random free port on `0.0.0.0`, serving the canary cert. Register a network alias / `/etc/hosts` entry so profiles can reach it by SNI hostname `canary-<uuid>.canary.internal`. Because all probe subprocesses run **inside the same container**, the simplest robust approach is:
- Bind to `127.0.0.1:<port>`.
- Append `127.0.0.1 canary-<uuid>.canary.internal` to `/etc/hosts` at cycle start, remove at cycle end (guard with a mutex; only one cycle at a time).

Server must staple OCSP when the profile requires it: fetch the OCSP response from Vault and set `tls.Certificate.OCSPStaple`. Provide a `stapling: on|off|stale` mode — `stale` staples a response fetched *before* revocation, which is exactly how a real attacker extends a compromised cert's life. This is a genuinely novel test case; make it a first-class feature.

**Verification:**
```bash
go test ./internal/canary/... -v
# and manually:
openssl s_client -connect 127.0.0.1:PORT -servername canary-x.canary.internal -status < /dev/null | grep "OCSP Response Status"
```

---

### Step 3.4 — Client profiles

**Target file:** `internal/profiles/registry.go` + `profiles.yaml`

**Action:** Implement at minimum these seven profiles. Each is a small wrapper around a subprocess or an in-process TLS connection. Expected baseline behavior distinguishes implementation defects from measured findings.

| Profile name | Implementation | Method | Expected baseline |
|---|---|---|---|
| `openssl-ocsp-direct` | `openssl ocsp -issuer chain.pem -cert leaf.pem -url <ocsp_url>` | ocsp_direct | rejected (this is the ground-truth oracle) |
| `curl-cert-status` | `curl --cacert chain.pem --cert-status https://<host>/` | ocsp_stapled | rejected when stapling on; **accepted when stapling off** |
| `curl-default` | `curl --cacert chain.pem https://<host>/` | none | accepted — curl does no revocation check by default |
| `go-tls-default` | in-process `crypto/tls` dial with RootCAs | none | accepted — Go stdlib does not check revocation |
| `go-tls-ocsp` | dial + explicit `ocsp.ParseResponse` on `ConnectionState().OCSPResponse` | ocsp_stapled | rejected when stapled |
| `python-requests` | `python3 -c` script with `verify=chain.pem` | none | accepted |
| `crl-check` | download CRL, parse with `x509.ParseRevocationList`, check serial | crl | rejected after CRL rebuild interval |

Add `chromium-headless` as an optional eighth profile behind a build flag — it is heavy and its CRLSet behaviour with a private CA is uninformative. Document why it is optional rather than silently omitting it.

`profiles.yaml` controls which profiles are enabled, poll interval, per-profile timeout, and max attempts.

**The headline finding this table produces:** most default client configurations accept a revoked certificate indefinitely. That is not a bug in the harness — it is the product's reason to exist, and the README must lead with it.

**Verification:**
```bash
go test ./internal/profiles/... -v
# each profile must be runnable standalone:
./bin/probe check --profile curl-default --target https://127.0.0.1:PORT --ca chain.pem
```

---

### Step 3.5 — Cycle runner

**Target file:** `internal/runner/runner.go`

**Action:** One cycle:
1. Issue canary cert (role `canary`, TTL 10m).
2. Start ephemeral TLS server with the configured stapling mode.
3. **Pre-flight:** run every profile once and assert all return `rejected == false` (i.e. the connection succeeds). If a profile fails here, the harness is broken; mark the cycle `error` and do not record a security metric. This guard prevents false "detection" from unrelated connectivity failures — do not skip it.
4. Revoke; record `t_revoke`.
5. For each profile in parallel, poll every `poll_interval` (default 2s) until `Outcome == rejected` or `max_wait` (default 180s) elapses. Record `t_detect`.
6. Timeout without rejection ⇒ `OutcomeAccepted` (soft-fail), recorded with `detection_seconds = max_wait` in a separate `+Inf`-style counter rather than polluting the histogram.
7. Tear down the server, remove the `/etc/hosts` entry, emit metrics, log a structured JSON summary.

Cycle interval: default 15m, configurable. Add a `--once` flag for CI and for `make demo-revoke`.

**Verification:**
```bash
./bin/probe run --once --config profiles.yaml | jq .
# output must contain one result object per enabled profile
```

---

### Step 3.6 — Prometheus metrics

**Target file:** `internal/metrics/metrics.go`

**Action:** Exactly these metric names (the Grafana dashboards and CI assertions in later phases depend on them — do not rename):

```
pki_revocation_detection_seconds{profile,method,stapling}      histogram
  buckets: 1,2,5,10,15,30,60,120,180

pki_revocation_softfail_total{profile,method,stapling}          counter
pki_revocation_detected_total{profile,method,stapling}          counter
pki_revocation_cycle_total{result}                              counter  # result=ok|error
pki_revocation_last_cycle_timestamp_seconds                     gauge
pki_ocsp_responder_latency_seconds                              histogram
pki_ocsp_responder_up                                           gauge
pki_crl_age_seconds                                             gauge
pki_crl_entries                                                 gauge
pki_cert_not_after_timestamp_seconds{cn,serial,source}          gauge
```

Serve on `:9110/metrics` plus `/healthz` and `/readyz`.

**Verification:**
```bash
curl -s localhost:9110/metrics | grep -E "^pki_revocation_(detection_seconds_bucket|softfail_total)"
# must be non-empty after one --once run
```

---

### Step 3.7 — Chaos mode (`tc netem`) — the CYB 260 experiment, productized

**Target files:** `internal/chaos/netem.go`, `scripts/chaos.sh`, `docker-compose.yml` (add `cap_add: [NET_ADMIN]` to the probe)

**Action:** A `--chaos` mode that sweeps injected latency on the path to the OCSP responder and records the soft-fail rate at each level. This directly reproduces the RQ1 experiment, but as a repeatable feature rather than a one-off lab run.

- Apply delay with `tc qdisc replace dev eth0 root netem delay ${D}ms` inside the probe container (requires `NET_ADMIN` and the `iproute2` package in the image).
- Sweep list configurable, default: `0,100,500,1000,1500,1700,1900,1950,1960,1970,1980,1990,2000` ms — deliberately dense near 2s, because the original research found the soft-fail transition is sharp but jittery in the 1960–2000 ms band rather than a clean step.
- N trials per level (default 5), full cycle per trial.
- Always `tc qdisc del dev eth0 root` in a deferred cleanup, and on SIGINT/SIGTERM. A leaked netem qdisc will silently poison every later measurement.
- Emit `pki_chaos_softfail_rate{delay_ms}` and write a CSV to `docs/benchmarks/data/chaos-<timestamp>.csv`.

**Verification:**
```bash
make chaos-sweep DELAYS=0,1000,2000 TRIALS=2
test -s docs/benchmarks/data/chaos-*.csv
docker compose exec revocation-probe tc qdisc show dev eth0 | grep -q netem && echo "FAIL: qdisc leaked" || echo OK
```

---

### Step 3.8 — Containerize and wire into Compose

**Target files:** `services/revocation-probe/Dockerfile`, `docker-compose.yml`

**Action:** Multi-stage build. The runtime stage **cannot** be distroless because profiles shell out to `curl`, `openssl`, `python3`, and `tc`. Use `alpine:3.20` with exactly: `curl openssl python3 py3-requests iproute2 ca-certificates`. Run as a non-root user with a `CAP_NET_ADMIN`-only grant. Document this deviation from the distroless standard in `SECURITY.md` — a reviewer will notice, and having the answer ready is the point.

Compose: mount `.data/approle/revocation-probe.env`, expose `${PROBE_METRICS_PORT}:9110`, `restart: unless-stopped`.

**Verification / Milestone (Phase 3 gate):**
```bash
make clean && make bootstrap
make demo-revoke        # runs one cycle with --once and pretty-prints the table
```
Expected output: a table where `openssl-ocsp-direct` shows `rejected` in a few seconds and at least two default-configuration profiles show `accepted` (soft-fail). Record this terminal output — it becomes the README demo GIF. Commit.

---

# PHASE 4 — Observability & Wazuh

**Goal:** Metrics, dashboards, alerts to Slack, and Vault audit logs parsed by custom Wazuh rules.
**Estimated effort:** 4–5 days.

### Step 4.1 — Prometheus

**Target files:** `observability/prometheus/prometheus.yml`, `docker-compose.observability.yml`

**Action:** Scrape jobs: `revocation-probe:9110`, `demo-api:8000`, `traefik:8080`, `prometheus` itself. `scrape_interval: 15s`, `evaluation_interval: 15s`. Load `rules/*.yml`. Point `alerting.alertmanagers` at `alertmanager:9093`.

Split observability into a second compose file so the core stack stays lightweight; `make up` starts core, `make up-full` starts core + observability via `-f docker-compose.yml -f docker-compose.observability.yml`.

**Verification:** `curl -s localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job:.labels.job, health}'` — all `up`.

---

### Step 4.2 — Alert rules (the SLO layer)

**Target file:** `observability/prometheus/rules/pki-slo.yml`

**Action:** Minimum five rules:

```yaml
- alert: RevocationSoftFailDetected
  expr: increase(pki_revocation_softfail_total{method!="none"}[30m]) > 0
  for: 1m
  labels: { severity: critical }
  annotations:
    summary: "Client profile {{ $labels.profile }} accepted a REVOKED certificate"
    runbook_url: "https://github.com/OWNER/pki-sentinel/blob/main/docs/runbooks/revocation-softfail.md"

- alert: RevocationDetectionSLOBreach
  expr: histogram_quantile(0.95, sum by (le,profile) (rate(pki_revocation_detection_seconds_bucket[1h]))) > 30
  for: 10m
  labels: { severity: warning }

- alert: OCSPResponderDown
  expr: pki_ocsp_responder_up == 0
  for: 5m
  labels: { severity: critical }

- alert: CRLStale
  expr: pki_crl_age_seconds > 86400
  for: 15m
  labels: { severity: warning }

- alert: CertificateExpiringSoon
  expr: (pki_cert_not_after_timestamp_seconds - time()) < 7*24*3600
  for: 30m
  labels: { severity: warning }

- alert: ProbeCycleFailing
  expr: increase(pki_revocation_cycle_total{result="error"}[1h]) > 2
  for: 5m
  labels: { severity: warning }
```

Note the deliberate exclusion of `method="none"` from the critical soft-fail alert: profiles that perform no revocation check at all are expected to accept, and alerting on them every cycle would be pure noise. They are still counted and displayed on the dashboard as the "structurally blind" cohort. Explain this distinction in the runbook — it is exactly the kind of alert-tuning judgment that separates a working system from a demo.

**Verification:**
```bash
docker run --rm -v $PWD/observability/prometheus:/w ${PROMETHEUS_IMAGE} promtool check rules /w/rules/pki-slo.yml
curl -s localhost:9090/api/v1/rules | jq -e '.data.groups | length > 0'
```

---

### Step 4.3 — Alertmanager → Slack

**Target file:** `observability/alertmanager/config.yml`

**Action:** Route by severity; `critical` → Slack channel immediately with `repeat_interval: 1h`; `warning` → grouped, `group_wait: 5m`. Read the webhook from `SLACK_WEBHOOK_URL` via `slack_api_url_file: /etc/alertmanager/slack_url` (mounted from a gitignored file), never inline. If `SLACK_WEBHOOK_URL` is empty, fall back to a `webhook_configs` receiver pointing at a local `webhook-logger` container so the alert path is still demonstrably functional without a real Slack workspace. This matters: a reviewer cloning the repo has no webhook, and a broken-looking alert path reads as an unfinished feature.

**Verification:**
```bash
make demo-revoke                                  # generates a soft-fail
curl -s localhost:9093/api/v2/alerts | jq -e 'length > 0'
docker compose logs webhook-logger | grep RevocationSoftFail
```

---

### Step 4.4 — Grafana dashboards

**Target files:** `observability/grafana/provisioning/datasources/prometheus.yml`, `provisioning/dashboards/default.yml`, `dashboards/{revocation-slo.json,cert-inventory.json,trust-drift.json}`

**Action:** Provision the datasource and dashboard folder so **no manual clicking is required** after `make up-full`. Build dashboards in the UI, then export JSON with `"__inputs"` stripped and the datasource pinned to the provisioned UID.

`revocation-slo.json` panels:
1. Stat: current soft-fail count in last 24h (thresholds: 0 green, ≥1 red).
2. Bar gauge: detection p50/p95 per profile.
3. Table: profile × method × last outcome — the client revocation-enforcement matrix.
4. Time series: OCSP responder latency.
5. **Heatmap: soft-fail rate vs injected delay** — the chaos-sweep chart. This panel is the direct descendant of the CYB 260 soft-fail-rate figure and should be the visual centerpiece.

**Verification:**
```bash
curl -su admin:${GRAFANA_ADMIN_PASSWORD} localhost:3000/api/search | jq -e 'length >= 3'
curl -su admin:${GRAFANA_ADMIN_PASSWORD} localhost:3000/api/datasources | jq -e '.[0].type == "prometheus"'
```

---

### Step 4.5 — `truststore-drift-agent`

**Target files:** `services/truststore-drift-agent/{main.go,Dockerfile}`, `observability/wazuh/rules/local_rules.xml`

**Action:** A small agent that enumerates the host trust store, computes SHA-256 over each root's SubjectPublicKeyInfo, and compares against a signed baseline.

Platform paths to support: `/etc/ssl/certs/ca-certificates.crt` and `/usr/local/share/ca-certificates/` (Debian/Ubuntu), `/etc/pki/ca-trust/` (RHEL), and macOS via `security dump-trust-settings -d` / `security find-certificate -a -p /Library/Keychains/System.keychain` when run natively.

Behaviour:
- `baseline` subcommand: writes `truststore-baseline.json` (list of SPKI hashes + subjects).
- `check` subcommand: diff against baseline; emit `pki_truststore_unknown_roots` gauge and a structured JSON event per added root to stdout and to `/var/log/pki-sentinel/truststore.json`.
- Exit code 1 on drift so it can be used as a cron/CI gate.

This is the productized form of the trusted-CA MITM finding: the original experiment proved a client with an attacker CA in its trust store accepts interception with zero warning and 100% success. Detection cannot happen at the TLS layer, so it has to happen at the trust-store layer. State that reasoning explicitly in the service's README.

**Verification:**
```bash
./bin/truststore-drift-agent baseline -o /tmp/baseline.json
# simulate a rogue CA install
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Rogue MITM CA" -out /tmp/rogue.pem -keyout /tmp/rogue.key
cp /tmp/rogue.pem /usr/local/share/ca-certificates/rogue.crt && update-ca-certificates
./bin/truststore-drift-agent check -b /tmp/baseline.json; echo "exit=$?"   # exit=1, event mentions "Rogue MITM CA"
```

---

### Step 4.6 — Wazuh (optional profile) + custom Vault audit decoder

**Target files:** `docker-compose.wazuh.yml`, `observability/wazuh/decoders/vault_audit.xml`, `observability/wazuh/rules/local_rules.xml`

**Action:** Wazuh single-node (manager + indexer + dashboard) is heavy — roughly 4 GB RAM. Put it behind a Compose **profile** (`profiles: ["wazuh"]`) and a separate `make up-wazuh`, so the default clone experience stays light. Document the RAM requirement in the README.

Enable the Vault file audit device (Terraform: `vault_audit` resource, `type = "file"`, `file_path = "/vault/logs/audit.json"`), mount that directory, and ship it with the Wazuh agent or Filebeat.

Vault audit entries are JSON, so use `<decoder name="vault-audit"><program_name>vault</program_name><plugin_decoder>JSON_Decoder</plugin_decoder></decoder>` and write rules keying on the JSON fields:

| Rule ID | Condition | Level | Meaning |
|---|---|---|---|
| 100100 | base rule, `type` field present | 0 | Vault audit event |
| 100101 | `request.path` matches `^pki_int/revoke` | 5 | Certificate revoked |
| 100102 | `request.path` matches `^pki_root/` and `request.operation != read` | 12 | **Root CA mount written — should essentially never happen** |
| 100103 | `error` field non-empty and `request.path` matches `^auth/` | 8 | Auth failure |
| 100104 | 5× rule 100103 in 60s, same `remote_address` | 10 | AppRole brute force |
| 100105 | `request.path` matches `^sys/policy` and operation is write/delete | 10 | Policy modified |
| 100106 | truststore-drift-agent event with `unknown_root` | 12 | Unauthorized root CA installed |

Rule 100102 is the highest-value rule in the set: with a properly bootstrapped hierarchy the root mount is written exactly once, so any later write is either an operator mistake or an attack.

**Verification:**
```bash
make up-wazuh
docker compose exec wazuh-manager /var/ossec/bin/wazuh-logtest < tests/fixtures/vault_audit_revoke.json
# must match rule id 100101
make demo-revoke
# then confirm the alert surfaced:
docker compose exec wazuh-manager grep -c '100101' /var/ossec/logs/alerts/alerts.json
```

**Milestone (Phase 4 gate):** `make up-full && make demo-revoke` → Grafana shows a soft-fail, Alertmanager fires, webhook-logger (or Slack) receives it, Wazuh logs rule 100101. Commit.

---

# PHASE 5 — CI/CD & Supply Chain

**Goal:** A pipeline that gates on security *properties*, not just on lint.
**Estimated effort:** 4–5 days.

### Step 5.1 — `ci.yml` — fast feedback

**Target file:** `.github/workflows/ci.yml`

**Action:** Triggers: `push` to `main`, `pull_request`. Jobs run in parallel, all with `permissions: contents: read` at workflow level and job-level escalation only where needed.

| Job | Steps |
|---|---|
| `lint-go` | setup-go with cache → `golangci-lint` (config in `.golangci.yml`, enable `gosec`, `errcheck`, `govet`, `staticcheck`) across all three services |
| `lint-iac` | `terraform fmt -check -recursive`, `terraform validate`, `tflint`, `checkov -d terraform/` |
| `lint-docker` | `hadolint` on every Dockerfile |
| `lint-shell` | `shellcheck scripts/**/*.sh` |
| `lint-compose` | `docker compose config -q` for each compose file combination |
| `unit-test` | `go test ./... -race -coverprofile=coverage.out` per service; upload coverage artifact |

**Verification:** `act -j lint-go` locally if available, otherwise push a branch and confirm green.

---

### Step 5.2 — `security-scan.yml`

**Target file:** `.github/workflows/security-scan.yml`

**Action:** Triggers: `push`, `pull_request`, and `schedule: cron '17 3 * * 1'` (weekly — catches newly disclosed CVEs in unchanged images).

| Step | Tool | Gate |
|---|---|---|
| Secret scan | `gitleaks/gitleaks-action` with `.gitleaks.toml` | fail on any finding |
| Filesystem vuln scan | `aquasecurity/trivy-action` mode `fs` | fail on `CRITICAL` |
| Image scan | `trivy-action` mode `image` per built image | fail on `CRITICAL,HIGH` with `ignore-unfixed: true` |
| IaC misconfig | `trivy config` + `checkov` | fail on `CRITICAL` |
| Policy | `conftest test terraform/ --policy policy/opa/` | fail on any deny |
| SAST | `github/codeql-action` for Go | upload SARIF |
| Dep review | `actions/dependency-review-action` on PRs | fail on high |

Upload every SARIF to the Security tab via `github/codeql-action/upload-sarif` (needs `security-events: write`).

Add `.trivyignore` **only** with a dated justification comment per entry. Unjustified ignores are worse than no scanning.

**Verification:** deliberately commit a fake AWS key on a scratch branch → gitleaks job must fail → revert.

---

### Step 5.3 — OPA policies

**Target files:** `policy/opa/{max_cert_ttl.rego,no_wildcard_san.rego,require_ocsp_aia.rego,require_short_lived_canary.rego}`

**Action:** Rego policies evaluated against the Terraform plan JSON (`terraform show -json plan.out`). Examples:
- `max_cert_ttl`: deny any `vault_pki_secret_backend_role` with `max_ttl_seconds > 90*24*3600`.
- `require_ocsp_aia`: deny if `vault_pki_secret_backend_config_urls.ocsp_servers` is empty.
- `no_wildcard_san`: deny `allow_glob_domains = true` combined with `allow_subdomains = true` on a server role.

**Verification:**
```bash
cd terraform/bootstrap && terraform plan -out=plan.out && terraform show -json plan.out > plan.json
conftest test plan.json --policy ../../policy/opa/
# then temporarily set max_ttl to 1 year and confirm the policy denies
```

---

### Step 5.4 — Integration test: assert the security property

**Target files:** `tests/integration/revocation_enforcement_test.go`, `.github/workflows/ci.yml` (add `integration` job)

**Action:** This is the step that makes the pipeline meaningful rather than decorative. The test:
1. Brings up the full stack in the runner (`docker compose up -d` + `wait_for_http` loops, hard 5-minute timeout).
2. Runs `bootstrap.sh` and `terraform apply`.
3. Executes one probe cycle with `--once --output json`.
4. Asserts:
   - `openssl-ocsp-direct` → `rejected` **and** `detection_seconds < 15`. If the ground-truth oracle cannot see a revocation within 15 s, the PKI itself is misconfigured.
   - `go-tls-ocsp` with stapling on → `rejected`.
   - Every profile with `method != "none"` → `rejected`.
   - Profiles with `method == "none"` → `accepted` (asserted as *expected*, with a comment explaining this is a documented property of those clients, not a defect in this project).
   - `pki_revocation_cycle_total{result="error"} == 0`.
5. Runs `truststore-drift-agent` against a synthetic rogue CA and asserts exit code 1.
6. Always `docker compose logs > artifacts/` and uploads on failure.

Mark it `//go:build integration` and run with `-tags=integration`.

**Verification:**
```bash
make test-integration        # local
# and: the job must be green in Actions, with a step summary printing the detection table
```

---

### Step 5.5 — `release.yml` — SBOM, signing, provenance

**Target file:** `.github/workflows/release.yml`

**Action:** Trigger on tag `v*`. Permissions: `contents: write`, `packages: write`, `id-token: write` (required for keyless signing).

1. `docker/setup-buildx-action`, `docker/login-action` → `ghcr.io`.
2. Build and push all three service images, multi-arch `linux/amd64,linux/arm64`, tagged with the git tag and the commit SHA.
3. `anchore/sbom-action` (syft) → SPDX JSON per image → attach to the GitHub Release.
4. `sigstore/cosign-installer` → `cosign sign --yes ghcr.io/OWNER/pki-sentinel/<svc>@<digest>` using the workflow's OIDC identity (**keyless** — no private key in secrets).
5. `cosign attest --predicate sbom.spdx.json --type spdxjson --yes <digest>`.
6. Generate SLSA provenance via `slsa-framework/slsa-github-generator`.
7. Publish release notes generated from Conventional Commits.

Add verification instructions to the README so a reviewer can actually check the signature:
```bash
cosign verify ghcr.io/OWNER/pki-sentinel/revocation-probe:v0.1.0 \
  --certificate-identity-regexp "https://github.com/OWNER/pki-sentinel/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**Verification:** tag `v0.0.1-rc1` on a branch, confirm release assets contain SBOMs and `cosign verify` succeeds against the pushed image.

---

### Step 5.6 — OpenSSF Scorecard + badges

**Target files:** `.github/workflows/scorecard.yml`, `README.md`

**Action:** Add the Scorecard action (weekly + on `main` push) publishing to the Security tab. Add badges: CI status, Scorecard score, license, Go report card, latest release. Also add `.github/dependabot.yml` covering `gomod`, `docker`, `github-actions`, and `terraform`.

**Milestone (Phase 5 gate):** all workflows green on `main`; a tagged release exists with signed images and SBOMs; the integration job's step summary shows the detection table. Commit.

---

# PHASE 6 — Docs, ADRs, Benchmarks

**Goal:** Make the repo legible in 60 seconds and defensible in a 60-minute interview.
**Estimated effort:** 1 week. Do not compress this phase — most of the perceived quality of an open-source project is decided here.

### Step 6.1 — `README.md`

**Target file:** `README.md`

**Action:** Exact section order:

1. **Title + one-liner**: "Internal PKI for SMEs with continuous evidence that clients reject revoked certificates."
2. **Badges** row.
3. **Demo GIF** (`docs/images/demo.gif`) — record with `charmbracelet/vhs`, script committed at `docs/images/demo.tape` so it is reproducible. Show: `make up` → `make demo-revoke` → the detection table with red soft-fail rows → the Grafana panel.
4. **Rationale** — three paragraphs. Paragraph 1: SMEs run internal services on self-signed or manually renewed certificates. Paragraph 2: organizations that deploy revocation rarely verify client enforcement. Paragraph 3: cite the prior measurement work — a controlled private-CA testbed showed that the OCSP soft-fail transition is a narrow, variable band rather than a clean threshold, with soft-fail rates reaching 100% at several delay points near the client timeout, and that a trusted-CA MITM succeeded in 100% of trials with no client-side indication. Link to `docs/benchmarks/`.
5. **Quick Start (3 commands)** — literally three lines, and they must work on a clean machine.
6. **Architecture** — the diagram, plus the three-plane table.
7. **Included capabilities** — bullet list of concrete capabilities.
8. **Try the demo** — `make demo-revoke`, `make chaos-sweep`, `make truststore-drift-demo`, each with expected output.
9. **Client profile results table** — the honest matrix showing which clients check revocation and which do not. This is the single most compelling artifact in the repo.
10. **Production notes** — see Step 6.4.
11. **Roadmap** — Kubernetes/Helm, HSM-backed root, cert-manager issuer, Windows trust-store agent, EST/SCEP.
12. **License, Acknowledgements, Prior work.**

**Verification:** hand the README to a reader with no context; they should be able to state what the project does and run it without asking a question.

---

### Step 6.2 — Architecture diagram

**Target files:** `docs/architecture.md`, `docs/images/architecture.svg`, `docs/diagrams/architecture.d2` (or `.drawio`)

**Action:** Commit the **source** of the diagram, not just the export — a PNG-only diagram cannot be maintained. Prefer D2 or Mermaid so CI can re-render it. Include a Mermaid version inline in `architecture.md` so it renders natively on GitHub. Show all three planes, with the Assurance plane visually centered and emphasized.

**Verification:** the Mermaid block renders on GitHub without syntax errors; `docs/images/architecture.svg` is regenerable via `make diagrams`.

---

### Step 6.3 — ADRs

**Target files:** `docs/adr/0001` … `0007`

**Action:** MADR format (Context / Decision Drivers / Considered Options / Decision Outcome / Consequences). Minimum set:

| ADR | Title | Must contain |
|---|---|---|
| 0001 | Vault/OpenBao over step-ca or Boulder | licensing (BUSL vs Apache-2.0), secret-management synergy, operational weight |
| 0002 | Transit auto-unseal instead of manual key shards | honest statement that the seal Vault is a demo stand-in for a cloud KMS |
| 0003 | Short-lived certificates over reliance on revocation | the whole project is evidence that revocation is unreliable; 24h TTL is the primary control, revocation is defense in depth |
| 0004 | Assurance plane as a first-class component | why measuring enforcement belongs in the product, not in a one-off lab |
| 0005 | Docker Compose over Kubernetes for v1 | clone-and-run time as the dominant adoption factor |
| 0006 | Alpine over distroless for the probe container | profiles require shell tooling; documented, scoped, scanned |
| 0007 | Alerting on `method != none` only | alert fatigue; blind clients are a reporting concern, not a paging concern |

**Verification:** every ADR has a status line (`Accepted` + date) and is linked from `docs/architecture.md`.

---

### Step 6.4 — `SECURITY.md`, threat model, "Production notes"

**Target files:** `SECURITY.md`, `docs/threat-model.md`, README §Production notes

**Action:** STRIDE table per plane. Then an explicit, unflinching list of what this deployment does *deliberately* insecurely for demo convenience, and the production remediation for each:

| Demo shortcut | Risk | Production fix |
|---|---|---|
| Root CA online in Vault | root key compromise = total trust failure | offline root on HSM/smartcard; sign the intermediate manually, annually |
| Transit auto-unseal via a second Vault | seal Vault compromise unseals everything | AWS KMS / GCP KMS / Azure Key Vault / HSM |
| Vault listener `tls_disable = true` | plaintext on the Docker bridge | TLS on the listener with a bootstrap cert |
| Recovery keys in `.data/vault-init.json` | plaintext key material on disk | PGP-encrypted shares distributed to separate key holders |
| `GRAFANA_ADMIN_PASSWORD` in `.env` | trivial credential | SSO/OIDC |
| ACME with no External Account Binding | any workload on the network can request a cert | `eab_policy: always-required` |

Including this table is not an admission of weakness — it is the clearest possible signal that the author understands the difference between a demo and a deployment.

**Verification:** every row in the table maps to a real setting present in the repo.

---

### Step 6.5 — Benchmarks chapter (the CYB 260 research, integrated)

**Target files:** `docs/benchmarks/README.md`, `docs/benchmarks/ocsp-softfail-thresholds.md`, `docs/benchmarks/trusted-ca-mitm.md`, `docs/benchmarks/data/*.csv`, `docs/benchmarks/figures/*.png`

**Action:** Structure as a short technical report, clearly separating the two data sources.

`ocsp-softfail-thresholds.md`:
- **Prior work (original testbed).** Methodology: private OpenSSL CA, Apache HTTPS server, macOS client polling via curl with OCSP verification enabled, `tc netem` delay injection on the OCSP path, detection time defined as the interval between the CA-side revocation timestamp and the first client-side verification failure. Findings: detection stable and fast at low delay; sharply unstable in the ~1950–2000 ms band; soft-fail rate 0% up to ~1955 ms, then 100% at 1960 ms, 0% at 1970 ms, 67% at 1980 ms, and 100% at 1990 and 2000 ms; detection-time distributions near 1950–1955 ms showing heavy right tails past 60 s. Include the three original figures. State the headline interpretation: **the soft-fail boundary is a jittery transition band, not a clean threshold, so mean detection time alone understates the risk — the tail is the risk.**
- **Limitations of the prior run.** Small trial counts at some delay levels, single client platform, single CA implementation. Say this plainly; acknowledged limitations read as rigor, unacknowledged ones read as inexperience.
- **Reproduction with pki-sentinel.** How `make chaos-sweep` reproduces the experiment on a different stack (Vault PKI instead of OpenSSL `ocsp`, multiple client profiles instead of one), with the new CSV/figures alongside. Note where results agree and where they diverge, and offer a hypothesis for any divergence.
- **Operational implication.** Because the enforcement boundary is latency-dependent and jittery, an adversary does not need to block the OCSP path — degrading it is sufficient. Therefore: prefer short-lived certificates, staple OCSP, hard-fail on high-risk paths, and monitor revocation enforcement continuously. Each of those maps to a feature in this repo; state the mapping.

`trusted-ca-mitm.md`: the Scenario A (untrusted CA → 0% interception success) and Scenario B (trusted CA → 100% success, full plaintext visible, no client warning) results, and the argument that this failure mode is undetectable at the TLS layer and must therefore be detected at the trust store — which is precisely what `truststore-drift-agent` does.

**Verification:** every numeric claim in the benchmark docs traces to a committed CSV or a cited figure. No number appears without a source.

---

### Step 6.6 — Runbooks

**Target files:** `docs/runbooks/{root-ca-compromise.md,vault-seal-recovery.md,rotate-intermediate.md,revocation-softfail.md,ocsp-responder-down.md}`

**Action:** Each runbook: Trigger (the exact alert name) → Impact → Immediate actions (numbered, copy-pasteable commands) → Verification → Post-incident. `revocation-softfail.md` and `ocsp-responder-down.md` must be reachable from the `runbook_url` annotation in the alert rules — a runbook link that 404s is worse than no link, so verify the paths resolve.

**Verification:** `grep -o 'runbook_url:.*' observability/prometheus/rules/*.yml` → every referenced path exists in the repo.

---

### Step 6.7 — Final polish

**Target files:** `CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`, `docs/images/demo.tape`

**Action:** Contribution guide with local dev setup and the commit convention. Issue templates for bug/feature/security. Record the demo GIF. Run a final clean-machine test:

```bash
git clone <repo> /tmp/clean-test && cd /tmp/clean-test
cp .env.example .env
make up
make demo-revoke
```

Time it. If it exceeds ~3 minutes on a laptop, optimize before release — clone-to-value time is the single strongest predictor of whether anyone actually runs the project.

**Final milestone:** tag `v1.0.0`, publish the release, and confirm the README renders correctly on GitHub with a working GIF and diagram.

---

## Appendix A — Consolidated Makefile targets (final state)

| Target | Purpose |
|---|---|
| `help` | list targets |
| `env` | create `.env` from example |
| `up` / `down` / `clean` | core stack lifecycle |
| `up-full` | core + observability |
| `up-wazuh` | core + observability + Wazuh profile |
| `bootstrap` | `up` + init Vault + terraform apply |
| `tf-init` / `tf-apply` / `tf-destroy` | Terraform lifecycle |
| `ca-chain` | export CA chain to `.data/ca_chain.pem` |
| `demo-revoke` | one probe cycle, pretty table |
| `chaos-sweep` | latency sweep, writes CSV |
| `truststore-drift-demo` | install a synthetic rogue CA, show detection |
| `lint` | all linters |
| `test` / `test-integration` | unit / integration tests |
| `scan` | trivy + gitleaks locally |
| `diagrams` | regenerate SVG from D2/Mermaid source |
| `logs` / `status` | operations |

## Appendix B — Definition of Done per phase

A phase is complete only when **all** of the following hold:
1. Its milestone command runs green from a clean state (`make clean` first).
2. `make lint` passes.
3. New behaviour has at least one test.
4. Docs touched by the phase are updated in the same commit.
5. No secret, key, or token is present in git history (`gitleaks detect --no-git=false`).
6. The change is committed with a Conventional Commit message referencing the phase.

## Appendix C — Common failure modes and their fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| Vault stays sealed after bootstrap | transit seal token wrong or `vault-seal` unreachable | check `docker compose logs vault \| grep -i seal`; verify `transit/keys/autounseal` exists |
| ACME directory returns 404 | mount tune headers or `config/cluster` missing | re-apply Step 2.1 in full; all three prerequisites are required |
| Traefik cannot solve the challenge | `api.internal` does not resolve from the Vault container | add network aliases; verify with `docker compose exec vault getent hosts api.internal` |
| Every profile reports `rejected` at cycle start | pre-flight guard missing or connectivity broken | implement Step 3.5 item 3; a "detection" before revocation is a harness bug |
| Detection times drift upward over time | leaked `netem` qdisc | `tc qdisc del dev eth0 root`; add the deferred cleanup |
| CRL profile never detects | full CRL did not regenerate after revocation or the probe is reading a stale CRL | verify baseline `auto_rebuild=false`, `enable_delta=false`; revoke again and confirm `/v1/pki_int/crl` changes before debugging the probe |
| Integration test flaky in CI | fixed sleeps instead of health polling | replace with `wait_for_http`; raise the bounded timeout, never the sleep |
