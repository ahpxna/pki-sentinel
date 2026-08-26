#!/usr/bin/env bash
# Runs only operational PKI/KV resources with the restricted Terraform
# AppRole. Bootstrap control-plane resources intentionally stay out of this
# target set because that credential must not administer policies, auth,
# mounts outside its named PKI/KV mounts, or audit devices.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

targets=(
  vault_mount.pki_root
  vault_pki_secret_backend_root_cert.root
  vault_pki_secret_backend_config_urls.root
  vault_mount.pki_int
  vault_pki_secret_backend_intermediate_cert_request.int
  vault_pki_secret_backend_root_sign_intermediate.int
  vault_pki_secret_backend_intermediate_set_signed.int
  vault_pki_secret_backend_config_urls.int
  vault_pki_secret_backend_config_cluster.int
  vault_pki_secret_backend_config_acme.int
  vault_generic_endpoint.int_crl_config
  vault_pki_secret_backend_role.server
  vault_pki_secret_backend_role.client
  vault_pki_secret_backend_role.canary
  vault_mount.kv
  random_password.demo_api_db_password
  vault_kv_secret_v2.demo_api_config
)

target_args=()
for target in "${targets[@]}"; do
  target_args+=("-target=${target}")
done

exec terraform -chdir="${REPO_ROOT}/terraform/bootstrap" "$@" "${target_args[@]}"
