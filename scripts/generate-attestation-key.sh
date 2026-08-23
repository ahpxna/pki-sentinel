#!/usr/bin/env bash
# Create a local Ed25519 keypair for demo assurance attestations. The private
# key stays under .data (ignored by Git); production should use an external
# KMS/HSM signer rather than copying this local pattern.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="${REPO_ROOT}/.data/attestation"
PRIVATE_KEY="${KEY_DIR}/assurance.key"
PUBLIC_KEY="${KEY_DIR}/assurance.pub"

mkdir -p "${KEY_DIR}"
chmod 700 "${KEY_DIR}"
if [[ -e "${PRIVATE_KEY}" || -e "${PUBLIC_KEY}" ]]; then
  echo "attestation key already exists: ${KEY_DIR}" >&2
  exit 1
fi

umask 077
openssl genpkey -algorithm ED25519 -out "${PRIVATE_KEY}"
openssl pkey -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
chmod 600 "${PRIVATE_KEY}"
chmod 644 "${PUBLIC_KEY}"
echo "created local attestation keypair under .data/attestation"
