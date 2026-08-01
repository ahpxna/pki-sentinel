resource "vault_mount" "pki_root" {
  path                  = "pki_root"
  type                  = "pki"
  description           = "Offline-style Root CA. Signs the intermediate only."
  max_lease_ttl_seconds = var.root_ttl_hours * 3600
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend              = vault_mount.pki_root.path
  type                 = "internal"
  common_name          = "${var.org_name} Root CA R1"
  ttl                  = "${var.root_ttl_hours}h"
  key_type             = "ec"
  key_bits             = 384
  exclude_cn_from_sans = true
  organization         = var.org_name
  ou                   = "PKI Sentinel"
}

resource "vault_pki_secret_backend_config_urls" "root" {
  backend                 = vault_mount.pki_root.path
  issuing_certificates    = ["${var.vault_public_addr}/v1/pki_root/ca"]
  crl_distribution_points = ["${var.vault_public_addr}/v1/pki_root/crl"]
}
