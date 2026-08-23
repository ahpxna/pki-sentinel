#!/usr/bin/env bash
# scripts/bootstrap.sh
#
# Initializes Vault (Raft storage, transit auto-unseal via vault-seal),
# hands a least-privilege token to Terraform, applies the PKI hierarchy, and
# revokes the initial root token. Reruns validate credentials and recover
# through Terraform AppRole instead of trusting file existence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/wait_for.sh
source "${SCRIPT_DIR}/lib/wait_for.sh"

require_bin docker curl jq terraform

if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

VAULT_ADDR="http://127.0.0.1:${VAULT_PORT:-8200}"
DATA_DIR="${REPO_ROOT}/.data"
INIT_FILE="${DATA_DIR}/vault-init.json"
TF_TOKEN_FILE="${DATA_DIR}/tf-token"
TF_APPROLE_FILE="${DATA_DIR}/approle/terraform.env"
TF_POLICY_FILE="${REPO_ROOT}/terraform/bootstrap/policies/terraform-bootstrap.hcl"
KEEP_ROOT="${PKI_SENTINEL_KEEP_ROOT:-0}"

mkdir -p "${DATA_DIR}/approle"

dc() { (cd "${REPO_ROOT}" && docker compose "$@"); }

echo "[bootstrap] 1/9 waiting for vault-seal to be reachable..."
wait_for_cmd 60 dc exec -T vault-seal vault status

echo "[bootstrap] 2/9 enabling transit engine + autounseal key on vault-seal (idempotent)..."
dc exec -T -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="${VAULT_SEAL_TOKEN}" \
  vault-seal vault secrets enable transit >/dev/null 2>&1 || true
dc exec -T -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="${VAULT_SEAL_TOKEN}" \
  vault-seal vault write -f transit/keys/autounseal >/dev/null 2>&1 || true

echo "[bootstrap] 3/9 restarting vault so it can reach the transit key..."
dc restart vault
wait_for_http "${VAULT_ADDR}/v1/sys/health?standbyok=true&uninitcode=501" 90 '^(2|3|5)[0-9][0-9]$'

INITIALIZED="$(curl -s "${VAULT_ADDR}/v1/sys/health" | jq -r '.initialized')"
if [[ "${INITIALIZED}" == "false" ]]; then
  echo "[bootstrap] 4/9 vault not yet initialized — running 'vault operator init'..."
  echo "[bootstrap]     NOTE: with transit auto-unseal these are RECOVERY keys, not unseal keys."
  dc exec -T -e VAULT_ADDR="http://127.0.0.1:8200" vault \
    vault operator init -recovery-shares=3 -recovery-threshold=2 -format=json > "${INIT_FILE}"
  chmod 600 "${INIT_FILE}"
elif [[ -f "${INIT_FILE}" ]]; then
	echo "[bootstrap] 4/9 ${INIT_FILE} already exists — skipping init (idempotent)."
else
  echo "[bootstrap] FATAL: Vault is initialized but ${INIT_FILE} is missing." >&2
  echo "[bootstrap] Recover an administrative token using the documented generate-root procedure; do not initialize again." >&2
  exit 1
fi

ROOT_TOKEN="$(jq -r '.root_token' "${INIT_FILE}")"
if [[ -z "${ROOT_TOKEN}" || "${ROOT_TOKEN}" == "null" ]]; then
  echo "[bootstrap] FATAL: could not extract root_token from ${INIT_FILE}" >&2
  exit 1
fi
export VAULT_ADDR

echo "[bootstrap] 5/9 asserting Vault auto-unsealed without any manual step..."
SEALED="$(curl -s "${VAULT_ADDR}/v1/sys/health" | jq -r '.sealed')"
if [[ "${SEALED}" != "false" ]]; then
  echo "[bootstrap] FATAL: Vault is still sealed. Auto-unseal is broken — check 'docker compose logs vault | grep -i seal'." >&2
  exit 1
fi
echo "[bootstrap]     sealed=false — auto-unseal confirmed."

token_is_valid() {
  local token="$1"
  [[ -n "${token}" ]] && [[ "$(curl -s -o /dev/null -w '%{http_code}' \
    --header "X-Vault-Token: ${token}" "${VAULT_ADDR}/v1/auth/token/lookup-self")" == "200" ]]
}

TF_TOKEN=""
if [[ -f "${TF_TOKEN_FILE}" ]]; then
  candidate="$(<"${TF_TOKEN_FILE}")"
  if token_is_valid "${candidate}"; then
    TF_TOKEN="${candidate}"
    echo "[bootstrap] 6/9 validated the existing Terraform token."
  fi
fi

if [[ -z "${TF_TOKEN}" && -f "${TF_APPROLE_FILE}" ]]; then
  role_id="$(sed -n 's/^VAULT_ROLE_ID=//p' "${TF_APPROLE_FILE}")"
  secret_id="$(sed -n 's/^VAULT_SECRET_ID=//p' "${TF_APPROLE_FILE}")"
  TF_TOKEN="$(curl -s --request POST \
    --data "$(jq -n --arg role_id "${role_id}" --arg secret_id "${secret_id}" '{role_id:$role_id,secret_id:$secret_id}')" \
    "${VAULT_ADDR}/v1/auth/approle/login" | jq -r '.auth.client_token // empty')"
  if token_is_valid "${TF_TOKEN}"; then
    printf '%s' "${TF_TOKEN}" > "${TF_TOKEN_FILE}"
    chmod 600 "${TF_TOKEN_FILE}"
    echo "[bootstrap] 6/9 obtained a fresh Terraform token through AppRole."
  else
    TF_TOKEN=""
  fi
fi

if [[ -z "${TF_TOKEN}" ]]; then
  if ! token_is_valid "${ROOT_TOKEN}"; then
    echo "[bootstrap] FATAL: Terraform credentials are invalid and the initial root token has already been revoked." >&2
    echo "[bootstrap] Follow docs/runbooks/vault-seal-recovery.md to generate a temporary administrative token, then rerun bootstrap." >&2
    exit 1
  fi
  echo "[bootstrap] 6/9 installing the least-privilege Terraform bootstrap policy..."
  policy_payload="$(jq -n --rawfile policy "${TF_POLICY_FILE}" '{policy:$policy}')"
  curl -fsS --request PUT \
    --header "X-Vault-Token: ${ROOT_TOKEN}" \
    --data "${policy_payload}" \
    "${VAULT_ADDR}/v1/sys/policies/acl/pki-sentinel-terraform" >/dev/null
  TF_TOKEN="$(curl -fsS --request POST \
    --header "X-Vault-Token: ${ROOT_TOKEN}" \
    --data '{"policies":["pki-sentinel-terraform"],"ttl":"30m","renewable":false}' \
    "${VAULT_ADDR}/v1/auth/token/create" | jq -r '.auth.client_token')"
  printf '%s' "${TF_TOKEN}" > "${TF_TOKEN_FILE}"
  chmod 600 "${TF_TOKEN_FILE}"
fi

echo "[bootstrap] 7/9 running terraform apply against terraform/bootstrap..."
(
  cd "${REPO_ROOT}/terraform/bootstrap"
  export VAULT_ADDR
  export VAULT_TOKEN="${TF_TOKEN}"
  terraform init -input=false
  terraform apply -auto-approve -input=false
)

echo "[bootstrap] 8/9 starting application services with generated AppRole credentials..."
dc --profile app up -d

echo "[bootstrap] 9/9 revoking the root token (guard: PKI_SENTINEL_KEEP_ROOT=1 to skip)..."
if [[ "${KEEP_ROOT}" == "1" ]]; then
  echo "[bootstrap]     PKI_SENTINEL_KEEP_ROOT=1 set — keeping root token for local iteration."
else
  if token_is_valid "${ROOT_TOKEN}"; then
    curl -s --request POST \
      --header "X-Vault-Token: ${ROOT_TOKEN}" \
      "${VAULT_ADDR}/v1/auth/token/revoke-self" >/dev/null
    echo "[bootstrap]"
    echo "[bootstrap] Root token revoked. Recovery keys are in .data/vault-init.json."
    echo "[bootstrap] To regain administrative access run 'vault operator generate-root'."
    echo "[bootstrap] See docs/runbooks/vault-seal-recovery.md."
  else
    echo "[bootstrap]     initial root token was already revoked; no action required."
  fi
fi

echo "[bootstrap] Done."
