# Vault ACME requires mount response/request headers, cluster configuration,
# and ACME configuration. Mount tuning is declared on vault_mount.pki_int so
# its state does not fight a second generic endpoint on every apply.

resource "vault_pki_secret_backend_config_acme" "int" {
  backend                  = vault_mount.pki_int.path
  enabled                  = true
  allowed_roles            = [vault_pki_secret_backend_role.server.name]
  default_directory_policy = "role:${vault_pki_secret_backend_role.server.name}"
  allowed_issuers          = ["*"]
  eab_policy               = "not-required"

  depends_on = [
    vault_pki_secret_backend_config_cluster.int,
  ]
}
