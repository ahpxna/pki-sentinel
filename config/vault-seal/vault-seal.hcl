# Reference configuration for the persistent local seal Vault. Compose writes
# the equivalent configuration into its protected administration volume.
ui = false
disable_mlock = true

storage "raft" {
  path    = "/vault/seal/data"
  node_id = "vault-seal-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://vault-seal:8200"
cluster_addr = "http://vault-seal:8201"
