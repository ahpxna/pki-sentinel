#!/usr/bin/env bash
# Wire the mounted Vault audit file into the live Wazuh manager logcollector.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml --profile app --profile wazuh)

cd "${REPO_ROOT}"

for _ in $(seq 1 120); do
  if "${COMPOSE[@]}" exec -T wazuh-manager test -s /var/ossec/etc/ossec.conf >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"${COMPOSE[@]}" exec -T wazuh-manager test -s /var/ossec/etc/ossec.conf

if "${COMPOSE[@]}" exec -T wazuh-manager grep -Fq '/var/ossec/logs/vault/audit.json' /var/ossec/etc/ossec.conf; then
  exit 0
fi

"${COMPOSE[@]}" exec -T wazuh-manager /bin/bash -euc '
  conf=/var/ossec/etc/ossec.conf
  tmp="${conf}.pki-sentinel.tmp"
  awk '\''
    BEGIN { inserted = 0 }
    !inserted && /<\/ossec_config>/ {
      print "  <localfile>"
      print "    <location>/var/ossec/logs/vault/audit.json</location>"
      print "    <log_format>json</log_format>"
      print "  </localfile>"
      inserted = 1
    }
    { print }
    END { if (!inserted) exit 42 }
  '\'' "$conf" > "$tmp"
  chmod --reference="$conf" "$tmp"
  chown --reference="$conf" "$tmp"
  mv -f "$tmp" "$conf"
  /var/ossec/bin/wazuh-control restart
'

for _ in $(seq 1 120); do
  status_output="$("${COMPOSE[@]}" exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null || true)"
  if grep -q 'wazuh-logcollector is running' <<<"${status_output}" && grep -q 'wazuh-analysisd is running' <<<"${status_output}"; then
    exit 0
  fi
  sleep 1
done

echo "wazuh: manager did not become ready after installing Vault audit localfile" >&2
exit 1
