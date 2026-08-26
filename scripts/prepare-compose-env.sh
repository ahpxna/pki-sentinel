#!/usr/bin/env bash
# Keep the ignored Compose env file in sync with the invoking developer's
# numeric UID/GID so writable bind mounts stay accessible on Linux hosts while
# the probe still runs as a non-root user inside the container.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
EXAMPLE_FILE="${REPO_ROOT}/.env.example"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${EXAMPLE_FILE}" "${ENV_FILE}"
fi

runtime_uid="$(id -u)"
runtime_gid="$(id -g)"
if [[ "${runtime_uid}" == "0" ]]; then
  # Never opt the application container into root just because setup itself
  # happened under sudo/root. Root can still manage files owned by this UID.
  runtime_uid=10001
  runtime_gid=10001
fi

upsert_env() {
  local key="$1"
  local value="$2"
  local tmp
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 {
      print key "=" value
      found = 1
      next
    }
    { print }
    END {
      if (!found) print key "=" value
    }
  ' "${ENV_FILE}" > "${tmp}"
  mv "${tmp}" "${ENV_FILE}"
}

upsert_env PROBE_RUNTIME_UID "${runtime_uid}"
upsert_env PROBE_RUNTIME_GID "${runtime_gid}"
