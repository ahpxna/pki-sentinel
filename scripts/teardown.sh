#!/usr/bin/env bash
# scripts/teardown.sh — full teardown: stack down, volumes removed, .data wiped.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
ENV_FILE="${REPO_ROOT}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  ENV_FILE="${REPO_ROOT}/.env.example"
fi

docker compose --env-file "${ENV_FILE}" \
  -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml \
  --profile app --profile tools --profile chaos --profile wazuh down -v --remove-orphans
if [[ -d .data ]]; then
  docker compose --env-file "${ENV_FILE}" -f docker-compose.yml \
    run --rm --no-deps state-cleaner
fi
rm -rf .data
rm -f terraform/bootstrap/terraform.tfstate terraform/bootstrap/terraform.tfstate.backup
echo "[teardown] done."
