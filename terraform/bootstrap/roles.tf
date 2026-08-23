resource "vault_pki_secret_backend_role" "server" {
  backend            = vault_mount.pki_int.path
  name               = "server"
  allowed_domains    = [var.pki_domain]
  allow_subdomains   = true
  allow_glob_domains = false
  server_flag        = true
  client_flag        = false
  key_type           = "ec"
  key_bits           = 256
  allow_ip_sans      = true
  no_store           = false
  max_ttl            = tostring(var.leaf_max_ttl_hours * 3600)
  ttl                = tostring(var.leaf_max_ttl_hours * 3600)
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
  max_ttl          = tostring(var.leaf_max_ttl_hours * 3600)
  ttl              = tostring(var.leaf_max_ttl_hours * 3600)
}

# Used exclusively by revocation-probe. The short TTL removes expired canaries
# from the CRL quickly and bounds CRL growth.
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
  ttl              = "600"
  max_ttl          = "1800"
}
