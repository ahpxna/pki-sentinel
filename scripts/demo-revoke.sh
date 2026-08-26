#!/usr/bin/env bash
# scripts/demo-revoke.sh — runs one probe cycle and pretty-prints the
# detection table. Backing implementation for `make demo-revoke`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_PATH="${REPO_ROOT}/.data/last-cycle.json"
ATTESTATION_DIR="${REPO_ROOT}/.data/attestation"
ATTESTATION_PATH="${ATTESTATION_DIR}/last-cycle.attestation.json"
mkdir -p "$(dirname "${REPORT_PATH}")"

ARGS=(run --once --output json)
SIGNED_RUN=false
if [[ -f "${ATTESTATION_DIR}/assurance.key" && -f "${ATTESTATION_DIR}/assurance.pub" ]]; then
  ARGS+=(--attestation-key /run/attestation/assurance.key --attestation-out /run/attestation/last-cycle.attestation.json)
  SIGNED_RUN=true
fi

(cd "${REPO_ROOT}" && docker compose exec -T revocation-probe probe "${ARGS[@]}" > "${REPORT_PATH}")

jq -r '"cycle \(.cycle_id)  scenario=\(.scenario)  revoke_ack_at=\(.revoke_ack_at)"' "${REPORT_PATH}"
jq -r '
  (["PROFILE", "ROLE", "METHOD", "DECISION", "REASON", "MATCH", "ATTEMPTS", "LATENCY"] | @tsv),
  (.results[] |
    ((.decision_latency_ns / 1000000 | floor | tostring) + "ms") as $latency |
    ([.profile, .role, .method, .decision, .reason, .expectation_met, .attempts, $latency] | @tsv))
' "${REPORT_PATH}" | column -t -s $'\t'

echo "[demo-revoke] machine-readable report: .data/last-cycle.json"
if [[ "${SIGNED_RUN}" == "true" ]]; then
  (cd "${REPO_ROOT}" && docker compose exec -T revocation-probe \
    probe attest verify --public-key /run/attestation/assurance.pub --input /run/attestation/last-cycle.attestation.json)
  echo "[demo-revoke] signed attestation: .data/attestation/last-cycle.attestation.json"
fi
