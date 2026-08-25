#!/usr/bin/env bash
# Verify every local Wazuh decoder and rule against a regression fixture.
# wazuh-logtest loads the same rule and decoder engine as Wazuh analysisd, but
# runs in an isolated session. This avoids making rule tests depend on the
# manager, indexer, and Filebeat startup sequence.
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

run_fixture() {
  local expected_rule="$1"
  local fixture="$2"
  local output
  # The image keeps its initial manager files in data_tmp until its normal
  # startup entrypoint restores them. Recreate that restore step, including
  # its exception files and runtime directories, then layer local rules on
  # top. Starting the complete manager service is unnecessary for an isolated
  # rule session.
  # shellcheck disable=SC2016 # The quoted program is evaluated by Bash inside the container.
  if ! output="$("${COMPOSE[@]}" run --quiet-pull --rm --no-deps -T \
    --entrypoint /bin/bash wazuh-manager -euc '
      source /permanent_data.env
      for permanent_dir in "${PERMANENT_DATA[@]}"; do
        mkdir -p "${permanent_dir}"
        cp -a "/var/ossec/data_tmp/permanent${permanent_dir}/." "${permanent_dir}/"
      done
      for exclusion_file in "${PERMANENT_DATA_EXCP[@]}"; do
        mkdir -p "$(dirname "${exclusion_file}")"
        cp -a "/var/ossec/data_tmp/exclusion${exclusion_file}" "${exclusion_file}"
      done
      if [[ -e /var/ossec/logs/ossec ]]; then
        mv -f /var/ossec/logs/ossec /var/ossec/logs/wazuh
      fi
      if [[ -e /var/ossec/queue/ossec ]]; then
        mv -f /var/ossec/queue/ossec /var/ossec/queue/sockets
      fi
      rm -f /var/ossec/queue/db/.template.db
      cp -a /wazuh-config-mount/etc/. /var/ossec/etc/
      /var/ossec/bin/wazuh-analysisd -f &
      analysisd_pid=$!
      cleanup() {
        kill "${analysisd_pid}" 2>/dev/null || true
        wait "${analysisd_pid}" 2>/dev/null || true
      }
      trap cleanup EXIT
      for _ in $(seq 1 100); do
        [[ -S /var/ossec/queue/sockets/analysis ]] && break
        if ! kill -0 "${analysisd_pid}" 2>/dev/null; then
          wait "${analysisd_pid}"
          exit 1
        fi
        sleep 0.1
      done
      [[ -S /var/ossec/queue/sockets/analysis ]]
      /var/ossec/bin/wazuh-logtest
    ' < "${fixture}" 2>&1)"; then
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
