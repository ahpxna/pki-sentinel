resource "vault_pki_secret_backend_config_urls" "int" {
  backend                 = vault_mount.pki_int.path
  issuing_certificates    = ["${var.vault_public_addr}/v1/pki_int/ca"]
  crl_distribution_points = ["${var.vault_public_addr}/v1/pki_int/crl"]
  ocsp_servers            = ["${var.vault_public_addr}/v1/pki_int/ocsp"]

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}

# CRL and OCSP behavior. delta_rebuild_interval=1m shortens the interval
# between revocation and CRL visibility. ocsp_expiry=1h balances responder
# load against propagation time. Benchmark context is documented in
# docs/benchmarks/ocsp-softfail-thresholds.md.
resource "vault_generic_endpoint" "int_crl_config" {
  path = "${vault_mount.pki_int.path}/config/crl"

  data_json = jsonencode({
    expiry                    = "72h"
    disable                   = false
    ocsp_disable              = false
    ocsp_expiry               = "1h"
    auto_rebuild              = true
    auto_rebuild_grace_period = "12h"
    enable_delta              = true
    delta_rebuild_interval    = "1m"
  })

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}

# Required for AIA and ACME to emit correct URLs.
resource "vault_generic_endpoint" "int_cluster_config" {
  path = "${vault_mount.pki_int.path}/config/cluster"

  data_json = jsonencode({
    path     = "${var.vault_acme_addr}/v1/${vault_mount.pki_int.path}"
    aia_path = "${var.vault_public_addr}/v1/${vault_mount.pki_int.path}"
  })

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}
