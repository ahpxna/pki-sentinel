#!/usr/bin/env bash
# Generate the shared internal bearer credential for the controller-to-executor
# API. The file is generated runtime state and is intentionally gitignored.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
token_file="${repo_root}/.data/executor.env"

if [[ -s "${token_file}" ]] && grep -q '^PROBE_EXECUTOR_TOKEN=.' "${token_file}"; then
  exit 0
fi

mkdir -p "$(dirname "${token_file}")"
umask 077
token="$(openssl rand -hex 32)"
printf 'PROBE_EXECUTOR_TOKEN=%s\n' "${token}" > "${token_file}"
chmod 0600 "${token_file}"
