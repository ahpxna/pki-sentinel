#!/usr/bin/env bash
# Generate the local-only certificate that lets Traefik expose Vault's ACME
# directory over HTTPS. The private key stays under ignored .data/ and is
# never part of an image or the repository.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TLS_DIR="${REPO_ROOT}/.data/traefik/bootstrap"
CERT_FILE="${TLS_DIR}/vault-acme.crt"
KEY_FILE="${TLS_DIR}/vault-acme.key"

command -v openssl >/dev/null 2>&1 || {
  echo "prepare-dev-tls: openssl is required" >&2
  exit 1
}

mkdir -p "${TLS_DIR}"
if [[ -s "${CERT_FILE}" && -s "${KEY_FILE}" ]] &&
  openssl x509 -checkend 86400 -noout -in "${CERT_FILE}" >/dev/null 2>&1; then
  exit 0
fi

umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
  -subj "/CN=vault-acme.internal/O=PKI Sentinel local demo" \
  -addext "subjectAltName=DNS:vault-acme.internal" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -out "${CERT_FILE}" -keyout "${KEY_FILE}" >/dev/null 2>&1

chmod 600 "${CERT_FILE}" "${KEY_FILE}"
echo "prepare-dev-tls: generated local certificate at ${CERT_FILE}"
