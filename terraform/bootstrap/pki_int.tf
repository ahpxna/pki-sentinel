resource "vault_mount" "pki_int" {
  path                  = "pki_int"
  type                  = "pki"
  description           = "Issuing CA. Signs server/client/canary leaf certificates."
  max_lease_ttl_seconds = var.int_ttl_hours * 3600
  allowed_response_headers = [
    "Last-Modified",
    "Location",
    "Replay-Nonce",
    "Link",
  ]
  passthrough_request_headers = ["If-Modified-Since"]
}

resource "vault_pki_secret_backend_intermediate_cert_request" "int" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = "${var.org_name} Issuing CA I1"
  key_type    = "ec"
  key_bits    = 256
}

resource "vault_pki_secret_backend_root_sign_intermediate" "int" {
  backend     = vault_mount.pki_root.path
  csr         = vault_pki_secret_backend_intermediate_cert_request.int.csr
  common_name = "${var.org_name} Issuing CA I1"
  format      = "pem_bundle"
  ttl         = "${var.int_ttl_hours}h"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "int" {
  backend = vault_mount.pki_int.path
  certificate = join("\n", [
    vault_pki_secret_backend_root_sign_intermediate.int.certificate,
    vault_pki_secret_backend_root_sign_intermediate.int.issuing_ca,
  ])
}
