#!/usr/bin/env bash
# scripts/teardown.sh — full teardown: stack down, volumes removed, .data wiped.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
docker compose down -v
rm -rf .data
echo "[teardown] done."
