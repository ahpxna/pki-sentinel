#!/usr/bin/env bash
# scripts/chaos.sh — thin wrapper around `probe chaos sweep` for `make chaos-sweep`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DELAYS="${DELAYS:-}"
TRIALS="${TRIALS:-5}"
OUT="${OUT:-}"

ARGS=(chaos sweep --trials "${TRIALS}")
[[ -n "${DELAYS}" ]] && ARGS+=(--delays "${DELAYS}")
[[ -n "${OUT}" ]] && ARGS+=(--out "${OUT}")

echo "[chaos] running one-shot fault runner: probe ${ARGS[*]}"
(cd "${REPO_ROOT}" && docker compose --profile chaos run --rm -T chaos-runner "${ARGS[@]}")
