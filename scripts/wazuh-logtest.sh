#!/usr/bin/env bash
# Verify that the mounted Wazuh decoder and rules classify a revocation audit
# event. This is deliberately a fixture gate, not a claim that the optional
# Wazuh profile is a complete production SIEM deployment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${REPO_ROOT}/tests/fixtures/vault_audit_revoke.json"

if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

output="$(cd "${REPO_ROOT}" && \
  docker compose -f docker-compose.yml -f docker-compose.wazuh.yml --profile wazuh \
    run --rm --no-deps -T --entrypoint /var/ossec/bin/wazuh-logtest wazuh-manager < "${FIXTURE}")"
printf '%s\n' "${output}"

if ! grep -Eq "id: '?100101'?|Rule: 100101" <<<"${output}"; then
  echo "wazuh-logtest did not match revocation rule 100101" >&2
  exit 1
fi
