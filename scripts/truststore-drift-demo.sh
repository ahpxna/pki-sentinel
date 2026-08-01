#!/usr/bin/env bash
# scripts/truststore-drift-demo.sh
#
# Baselines a demo trust store, installs a synthetic rogue CA into it, and
# shows truststore-drift-agent detect the drift. Uses a dedicated,
# container-local demo trust store (./.data/truststore/extra-cas) — never
# the developer's real host trust store.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p .data/truststore/extra-cas
dc() { docker compose run --rm -T truststore-drift-agent "$@"; }

echo "[truststore-drift-demo] 1/3 baselining the demo trust store..."
dc baseline -o /data/baseline.json

echo "[truststore-drift-demo] 2/3 installing a synthetic rogue CA..."
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=Rogue MITM CA" \
  -out .data/truststore/extra-cas/rogue.crt -keyout .data/truststore/rogue.key 2>/dev/null

echo "[truststore-drift-demo] 3/3 checking for drift (expect exit=1, event mentions 'Rogue MITM CA')..."
set +e
dc check -b /data/baseline.json
status=$?
set -e
echo "[truststore-drift-demo] exit=${status}"
exit "${status}"
