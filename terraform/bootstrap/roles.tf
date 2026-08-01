resource "vault_pki_secret_backend_role" "server" {
  backend          = vault_mount.pki_int.path
  name             = "server"
  allowed_domains  = [var.pki_domain]
  allow_subdomains = true
  allow_glob_domains = false
  server_flag      = true
  client_flag      = false
  key_type         = "ec"
  key_bits         = 256
  allow_ip_sans    = true
  no_store         = false
  max_ttl          = "${var.leaf_max_ttl_hours}h"
  ttl              = "${var.leaf_max_ttl_hours}h"
}

resource "vault_pki_secret_backend_role" "client" {
  backend          = vault_mount.pki_int.path
  name             = "client"
  allowed_domains  = [var.pki_domain]
  allow_subdomains = true
  server_flag      = false
  client_flag      = true
  key_type         = "ec"
  key_bits         = 256
  no_store         = false
  max_ttl          = "${var.leaf_max_ttl_hours}h"
  ttl              = "${var.leaf_max_ttl_hours}h"
}

# Used exclusively by revocation-probe. Short TTL so revoked canaries expire
# out of the CRL quickly and the CRL does not grow unbounded.
resource "vault_pki_secret_backend_role" "canary" {
  backend          = vault_mount.pki_int.path
  name             = "canary"
  allowed_domains  = ["canary.${var.pki_domain}"]
  allow_subdomains = true
  server_flag      = true
  client_flag      = false
  key_type         = "ec"
  key_bits         = 256
  no_store         = false
  ttl              = "10m"
  max_ttl          = "30m"
}
