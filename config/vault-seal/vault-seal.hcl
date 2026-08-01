# vault-seal runs in dev mode (see docker-compose.yml VAULT_DEV_* env vars),
# so this file is currently unused but kept for parity if vault-seal is later
# switched to production (non-dev) mode.
ui = true
disable_mlock = true

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-seal-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://vault-seal:8200"
cluster_addr = "http://vault-seal:8201"
