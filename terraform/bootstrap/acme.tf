# Vault ACME requires three resources before the directory endpoint is available:
#  1. mount tune with allowed_response_headers / passthrough_request_headers
#  2. pki_int/config/cluster (see pki_int_config.tf)
#  3. pki_int/config/acme (this file)

resource "vault_generic_endpoint" "pki_int_acme_tune" {
  path = "sys/mounts/${vault_mount.pki_int.path}/tune"

  data_json = jsonencode({
    allowed_response_headers = [
      "Last-Modified",
      "Location",
      "Replay-Nonce",
      "Link",
    ]
    passthrough_request_headers = [
      "If-Modified-Since",
    ]
  })
}

resource "vault_generic_endpoint" "int_acme_config" {
  path = "${vault_mount.pki_int.path}/config/acme"

  data_json = jsonencode({
    enabled                  = true
    allowed_roles            = [vault_pki_secret_backend_role.server.name]
    default_directory_policy = "role:${vault_pki_secret_backend_role.server.name}"
    allowed_issuers          = ["*"]
    eab_policy               = "not-required"
  })

  depends_on = [
    vault_generic_endpoint.pki_int_acme_tune,
    vault_generic_endpoint.int_cluster_config,
  ]
}
