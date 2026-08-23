#!/usr/bin/env bash
# scripts/gen-slack-url-file.sh
# Writes .data/alertmanager/slack_url from SLACK_WEBHOOK_URL so Alertmanager
# always has a file to mount at /etc/alertmanager/slack_url, even when the
# env var is empty (Slack receivers then simply have nowhere to send, and
# the webhook-logger fallback receiver — see observability/alertmanager/config.yml —
# still demonstrates the alert path).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${REPO_ROOT}/.data/alertmanager" \
  "${REPO_ROOT}/.data/truststore/published" \
  "${REPO_ROOT}/.data/truststore/extra-cas" \
  "${REPO_ROOT}/.data/truststore/events"
if [[ -f "${REPO_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.env"
  set +a
fi
printf '%s' "${SLACK_WEBHOOK_URL:-}" > "${REPO_ROOT}/.data/alertmanager/slack_url"
