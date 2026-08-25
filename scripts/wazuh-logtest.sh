#!/usr/bin/env bash
# Start a real Wazuh manager, wait for wazuh-analysisd, and verify every local
# PKI Sentinel rule against a regression fixture. Running wazuh-logtest as the
# container entrypoint is insufficient because it needs the analysis daemon.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh)

if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

cd "${REPO_ROOT}"
manager_was_running=0
if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx 'wazuh-manager'; then
  manager_was_running=1
fi
cleanup() {
  if [[ "${manager_was_running}" -eq 0 ]]; then
    "${COMPOSE[@]}" rm -sf wazuh-manager >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d --no-deps wazuh-manager

analysisd_ready=0
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-analysisd is running'; then
    analysisd_ready=1
    break
  fi
  if ! "${COMPOSE[@]}" ps --status running wazuh-manager | grep -q wazuh-manager; then
    break
  fi
  sleep 1
done
if [[ "${analysisd_ready}" -ne 1 ]]; then
  echo "wazuh-analysisd did not become ready" >&2
  "${COMPOSE[@]}" ps --all >&2 || true
  "${COMPOSE[@]}" logs --no-color --tail=120 wazuh-manager >&2 || true
  exit 1
fi

run_fixture() {
  local expected_rule="$1"
  local fixture="$2"
  local output
  if ! output="$("${COMPOSE[@]}" exec -T wazuh-manager /var/ossec/bin/wazuh-logtest < "${fixture}" 2>&1)"; then
    printf '%s\n' "${output}" >&2
    echo "wazuh-logtest failed for ${fixture}" >&2
    return 1
  fi
  printf '%s\n' "${output}"
  if ! grep -Eq "id: '?${expected_rule}'?|Rule: ${expected_rule}" <<<"${output}"; then
    echo "wazuh-logtest did not match rule ${expected_rule} for ${fixture}" >&2
    return 1
  fi
}

run_fixture 100101 "${REPO_ROOT}/tests/fixtures/vault_audit_revoke.json"
run_fixture 100102 "${REPO_ROOT}/tests/fixtures/vault_audit_root_write.json"
run_fixture 100103 "${REPO_ROOT}/tests/fixtures/vault_audit_auth_failure.json"
run_fixture 100104 "${REPO_ROOT}/tests/fixtures/vault_audit_auth_bruteforce.jsonl"
run_fixture 100105 "${REPO_ROOT}/tests/fixtures/vault_audit_policy_write.json"
run_fixture 100106 "${REPO_ROOT}/tests/fixtures/truststore_unknown_root.json"
