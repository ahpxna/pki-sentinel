resource "vault_pki_secret_backend_config_urls" "int" {
  backend                 = vault_mount.pki_int.path
  issuing_certificates    = ["${var.vault_public_addr}/v1/pki_int/ca"]
  crl_distribution_points = ["${var.vault_public_addr}/v1/pki_int/crl"]
  ocsp_servers            = ["${var.vault_public_addr}/v1/pki_int/ocsp"]

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}

# CRL and OCSP behavior. The baseline assurance oracle consumes the full /crl
# endpoint and expects a successful revocation to be reflected immediately.
# Vault disables immediate CRL regeneration when auto_rebuild is enabled, so
# periodic/delta rebuilding is deliberately disabled for this baseline. Faulted
# publication timing belongs in an explicit assurance scenario, not issuer drift.
resource "vault_generic_endpoint" "int_crl_config" {
  path                 = "${vault_mount.pki_int.path}/config/crl"
  ignore_absent_fields = true

  data_json = jsonencode({
    expiry        = "72h"
    disable       = false
    ocsp_disable  = false
    ocsp_expiry   = "1h"
    auto_rebuild  = false
    enable_delta  = false
  })

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}

# Required for AIA and ACME to emit correct URLs.
resource "vault_pki_secret_backend_config_cluster" "int" {
  backend  = vault_mount.pki_int.path
  path     = "${var.vault_acme_addr}/v1/${vault_mount.pki_int.path}"
  aia_path = "${var.vault_public_addr}/v1/${vault_mount.pki_int.path}"

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}
