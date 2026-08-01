path "pki_int/acme/*" {
  capabilities = ["read", "create", "update"]
}

path "pki_int/roles/server" {
  capabilities = ["read"]
}
