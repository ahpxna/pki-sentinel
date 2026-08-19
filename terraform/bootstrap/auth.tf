resource "vault_auth_backend" "approle" {
  type = "approle"
}

locals {
  approle_services = {
    demo-api = {
      policies = [vault_policy.demo_api.name]
    }
    revocation-probe = {
      policies = [vault_policy.revocation_probe.name]
    }
    traefik-acme = {
      policies = [vault_policy.traefik_acme.name]
    }
  }
}

resource "vault_approle_auth_backend_role" "service" {
  for_each       = local.approle_services
  backend        = vault_auth_backend.approle.path
  role_name      = each.key
  token_policies = each.value.policies
  token_ttl      = 3600
  token_max_ttl  = 14400
  secret_id_ttl  = 86400
}

data "vault_approle_auth_backend_role_id" "service" {
  for_each  = local.approle_services
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.service[each.key].role_name
}

resource "vault_approle_auth_backend_role_secret_id" "service" {
  for_each  = local.approle_services
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.service[each.key].role_name
}

# Store generated credentials under the ignored .data/ directory for direct
# service and Compose mounts.
resource "local_sensitive_file" "approle_env" {
  for_each        = local.approle_services
  filename        = "${path.module}/../../.data/approle/${each.key}.env"
  content         = <<-ENV
    VAULT_ROLE_ID=${data.vault_approle_auth_backend_role_id.service[each.key].role_id}
    VAULT_SECRET_ID=${vault_approle_auth_backend_role_secret_id.service[each.key].secret_id}
  ENV
  file_permission = "0600"
}
