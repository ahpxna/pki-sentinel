#!/usr/bin/env bash
# scripts/bootstrap.sh
#
# Initializes Vault (Raft storage, transit auto-unseal via vault-seal),
# hands a Terraform-scoped token off to Terraform, applies the PKI hierarchy,
# and revokes the root token at the end (see Step 1.9 / docs/runbooks/vault-seal-recovery.md).
#
# Idempotent: safe to run twice.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/wait_for.sh
source "${SCRIPT_DIR}/lib/wait_for.sh"

require_bin docker curl jq

if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

VAULT_ADDR="http://127.0.0.1:${VAULT_PORT:-8200}"
VAULT_SEAL_ADDR="http://127.0.0.1:${VAULT_SEAL_PORT:-8210}"
DATA_DIR="${REPO_ROOT}/.data"
INIT_FILE="${DATA_DIR}/vault-init.json"
TF_TOKEN_FILE="${DATA_DIR}/tf-token"
KEEP_ROOT="${PKI_SENTINEL_KEEP_ROOT:-0}"

mkdir -p "${DATA_DIR}"

dc() { (cd "${REPO_ROOT}" && docker compose "$@"); }

echo "[bootstrap] 1/8 waiting for vault-seal to be reachable..."
wait_for_http "${VAULT_SEAL_ADDR}/v1/sys/health" 60 '^(2|4|5)[0-9][0-9]$'

echo "[bootstrap] 2/8 enabling transit engine + autounseal key on vault-seal (idempotent)..."
dc exec -T -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="${VAULT_SEAL_TOKEN}" \
  vault-seal vault secrets enable transit >/dev/null 2>&1 || true
dc exec -T -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="${VAULT_SEAL_TOKEN}" \
  vault-seal vault write -f transit/keys/autounseal >/dev/null 2>&1 || true

echo "[bootstrap] 3/8 restarting vault so it can reach the transit key..."
dc restart vault
wait_for_http "${VAULT_ADDR}/v1/sys/health?standbyok=true&uninitcode=501" 90 '^(2|3|5)[0-9][0-9]$'

if [[ ! -f "${INIT_FILE}" ]]; then
  echo "[bootstrap] 4/8 vault not yet initialized — running 'vault operator init'..."
  echo "[bootstrap]     NOTE: with transit auto-unseal these are RECOVERY keys, not unseal keys."
  dc exec -T -e VAULT_ADDR="http://127.0.0.1:8200" vault \
    vault operator init -recovery-shares=3 -recovery-threshold=2 -format=json > "${INIT_FILE}"
  chmod 600 "${INIT_FILE}"
else
  echo "[bootstrap] 4/8 ${INIT_FILE} already exists — skipping init (idempotent)."
fi

ROOT_TOKEN="$(jq -r '.root_token' "${INIT_FILE}")"
if [[ -z "${ROOT_TOKEN}" || "${ROOT_TOKEN}" == "null" ]]; then
  echo "[bootstrap] FATAL: could not extract root_token from ${INIT_FILE}" >&2
  exit 1
fi
export VAULT_TOKEN="${ROOT_TOKEN}"
export VAULT_ADDR

echo "[bootstrap] 5/8 asserting Vault auto-unsealed without any manual step..."
SEALED="$(curl -s "${VAULT_ADDR}/v1/sys/health" | jq -r '.sealed')"
if [[ "${SEALED}" != "false" ]]; then
  echo "[bootstrap] FATAL: Vault is still sealed. Auto-unseal is broken — check 'docker compose logs vault | grep -i seal'." >&2
  exit 1
fi
echo "[bootstrap]     sealed=false — auto-unseal confirmed."

if [[ ! -f "${TF_TOKEN_FILE}" ]]; then
  echo "[bootstrap] 6/8 creating a Terraform-scoped token (root policy, 60m period)..."
  curl -s --request POST \
    --header "X-Vault-Token: ${ROOT_TOKEN}" \
    --data '{"policies":["root"],"period":"60m"}' \
    "${VAULT_ADDR}/v1/auth/token/create" | jq -r '.auth.client_token' > "${TF_TOKEN_FILE}"
  chmod 600 "${TF_TOKEN_FILE}"
else
  echo "[bootstrap] 6/8 ${TF_TOKEN_FILE} already exists — skipping (idempotent)."
fi

echo "[bootstrap] 7/8 running terraform apply against terraform/bootstrap..."
TF_TOKEN="$(cat "${TF_TOKEN_FILE}")"
(
  cd "${REPO_ROOT}/terraform/bootstrap"
  export VAULT_ADDR
  export VAULT_TOKEN="${TF_TOKEN}"
  terraform init -input=false
  terraform apply -auto-approve -input=false
)

echo "[bootstrap] 8/8 revoking the root token (guard: PKI_SENTINEL_KEEP_ROOT=1 to skip)..."
if [[ "${KEEP_ROOT}" == "1" ]]; then
  echo "[bootstrap]     PKI_SENTINEL_KEEP_ROOT=1 set — keeping root token for local iteration."
else
  curl -s --request POST \
    --header "X-Vault-Token: ${ROOT_TOKEN}" \
    "${VAULT_ADDR}/v1/auth/token/revoke-self" >/dev/null || true
  echo "[bootstrap]"
  echo "[bootstrap] Root token revoked. Recovery keys are in .data/vault-init.json."
  echo "[bootstrap] To regain root access run 'vault operator generate-root'."
  echo "[bootstrap] See docs/runbooks/vault-seal-recovery.md."
fi

echo "[bootstrap] Done."
