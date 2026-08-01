#!/usr/bin/env bash
# scripts/demo-revoke.sh — runs one probe cycle and pretty-prints the
# detection table. Backing implementation for `make demo-revoke`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
(cd "${REPO_ROOT}" && docker compose exec -T revocation-probe probe run --once)
