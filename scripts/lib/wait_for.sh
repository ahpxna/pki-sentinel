#!/usr/bin/env bash
# scripts/lib/wait_for.sh
# Reusable synchronization helpers. Never use `sleep N` as a sync primitive
# elsewhere in this repo — source this file and use these functions instead.
set -euo pipefail

# Usage: wait_for_http <url> <timeout_seconds> [expected_http_codes_regex]
wait_for_http() {
  local url="$1" timeout="${2:-60}" ok="${3:-^(2|3)[0-9][0-9]$}"
  local start
  start=$(date +%s)
  while true; do
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' -k --max-time 3 "$url" || echo 000)
    if [[ "$code" =~ $ok ]]; then
      echo "[wait_for] $url ready (HTTP $code)"
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      echo "[wait_for] TIMEOUT after ${timeout}s waiting for $url (last=$code)" >&2
      return 1
    fi
    sleep 1
  done
}

# Usage: wait_for_cmd <timeout_seconds> <command...>
wait_for_cmd() {
  local timeout="$1"; shift
  local start
  start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if (( $(date +%s) - start > timeout )); then
      echo "[wait_for] TIMEOUT running: $*" >&2
      return 1
    fi
    sleep 1
  done
  return 0
}

# Usage: require_bin <bin1> [bin2 ...]
require_bin() {
  for b in "$@"; do
    command -v "$b" >/dev/null || { echo "Missing required binary: $b" >&2; return 1; }
  done
}
