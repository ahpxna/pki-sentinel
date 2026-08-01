ui = true
disable_mlock = true

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # TLS terminated by Traefik in Phase 2; documented in docs/threat-model.md
}

seal "transit" {
  address         = "http://vault-seal:8200"
  disable_renewal = "false"
  key_name        = "autounseal"
  mount_path      = "transit/"
  tls_skip_verify = "true"
  # No `token` field here: the transit seal client authenticates using the
  # VAULT_TOKEN environment variable set on the `vault` container (see
  # docker-compose.yml and docs/adr/0002-auto-unseal-tradeoffs.md).
}

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"
