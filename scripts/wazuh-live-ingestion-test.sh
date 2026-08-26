#!/usr/bin/env bash
# Prove the live path: Vault audit device -> mounted file -> Wazuh logcollector
# -> JSON decoder/rule engine -> alerts.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml --profile app --profile wazuh)

if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi

cd "${REPO_ROOT}"
./scripts/wazuh-configure-vault-audit.sh

audit_file="${REPO_ROOT}/.data/vault-logs/audit.json"
if [[ ! -f "${audit_file}" ]]; then
  echo "wazuh-live-ingestion-test: ${audit_file} does not exist; run make bootstrap before make up-wazuh" >&2
  exit 1
fi
before_lines="$(wc -l < "${audit_file}")"
before_alert_lines="$("${COMPOSE[@]}" exec -T wazuh-manager /bin/bash -euc \
  'if [[ -f /var/ossec/logs/alerts/alerts.json ]]; then wc -l < /var/ossec/logs/alerts/alerts.json; else echo 0; fi')"

# An intentionally invalid token produces a real Vault audit response with
# request.path=auth/token/lookup-self and error=permission denied (rule 100103).
# curl itself is expected to receive HTTP 403, so do not use --fail here.
http_code="$(curl -sS -o /tmp/pki-sentinel-wazuh-auth-failure.json -w '%{http_code}' \
  -H 'X-Vault-Token: pki-sentinel-invalid-wazuh-live-test' \
  "http://127.0.0.1:${VAULT_PORT:-8200}/v1/auth/token/lookup-self")"
if [[ "${http_code}" != "403" ]]; then
  echo "wazuh-live-ingestion-test: expected Vault HTTP 403, got ${http_code}" >&2
  cat /tmp/pki-sentinel-wazuh-auth-failure.json >&2 || true
  exit 1
fi

for _ in $(seq 1 100); do
  if (( $(wc -l < "${audit_file}") > before_lines )); then
    break
  fi
  sleep 0.2
done
if (( $(wc -l < "${audit_file}") <= before_lines )); then
  echo "wazuh-live-ingestion-test: Vault audit file did not record the live request" >&2
  exit 1
fi

first_new_alert_line=$((before_alert_lines + 1))
for _ in $(seq 1 150); do
  if "${COMPOSE[@]}" exec -T wazuh-manager /bin/bash -euc '
      test -f /var/ossec/logs/alerts/alerts.json
      tail -n +"$1" /var/ossec/logs/alerts/alerts.json \
        | grep -F '\''"id":"100103"'\'' \
        | grep -Fq '\''Vault auth failure'\''
    ' _ "${first_new_alert_line}" >/dev/null 2>&1; then
    echo "wazuh live ingestion: PASS (Vault audit -> rule 100103)"
    exit 0
  fi
  sleep 0.2
done

"${COMPOSE[@]}" exec -T wazuh-manager tail -n 80 /var/ossec/logs/alerts/alerts.json >&2 || true
echo "wazuh-live-ingestion-test: live Vault audit event never reached Wazuh rule 100103" >&2
exit 1
