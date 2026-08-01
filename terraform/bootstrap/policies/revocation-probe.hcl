# revocation-probe must never be able to touch pki_root, and must never get sudo.
path "pki_int/issue/canary" {
  capabilities = ["update"]
}

path "pki_int/revoke" {
  capabilities = ["update"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/crl" {
  capabilities = ["read"]
}
