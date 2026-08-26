resource "vault_policy" "demo_api" {
  name   = "demo-api"
  policy = file("${path.module}/policies/demo-api.hcl")
}

resource "vault_policy" "revocation_probe" {
  name   = "revocation-probe"
  policy = file("${path.module}/policies/revocation-probe.hcl")
}

resource "vault_policy" "traefik_acme" {
  name   = "traefik-acme"
  policy = file("${path.module}/policies/traefik-acme.hcl")
}

resource "vault_mount" "kv" {
  path        = "kv"
  type        = "kv-v2"
  description = "Application secrets."
}

resource "random_password" "demo_api_db_password" {
  length  = 24
  special = true
}

resource "vault_kv_secret_v2" "demo_api_config" {
  mount = vault_mount.kv.path
  name  = "demo-api/config"
  data_json = jsonencode({
    db_password = random_password.demo_api_db_password.result
  })
}
