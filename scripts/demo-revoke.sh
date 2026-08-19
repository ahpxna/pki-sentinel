#!/usr/bin/env bash
# scripts/demo-revoke.sh — runs one probe cycle and pretty-prints the
# detection table. Backing implementation for `make demo-revoke`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_PATH="${REPO_ROOT}/.data/last-cycle.json"
mkdir -p "$(dirname "${REPORT_PATH}")"

(cd "${REPO_ROOT}" && docker compose exec -T revocation-probe \
  probe run --once --output json > "${REPORT_PATH}")

jq -r '"cycle \(.cycle_id)  revoked_at=\(.revoked_at)"' "${REPORT_PATH}"
jq -r '
  (["PROFILE", "METHOD", "OUTCOME", "ATTEMPTS", "DETECTION"] | @tsv),
  (.results[] |
    (if .outcome == "rejected" then
      ((.detection_duration_ns / 1000000 | floor | tostring) + "ms")
    else "-" end) as $detection |
    ([.profile, .method, .outcome, .attempts, $detection] | @tsv))
' "${REPORT_PATH}" | column -t -s $'\t'

echo "[demo-revoke] machine-readable report: .data/last-cycle.json"
