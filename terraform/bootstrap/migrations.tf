# State-only migration from generic endpoints to first-class Vault provider
# resources. These endpoints either do not support DELETE or represent mount
# tuning now owned by vault_mount.pki_int; removing their old addresses must
# not mutate the live Vault configuration.
removed {
  from = vault_generic_endpoint.int_acme_config

  lifecycle {
    destroy = false
  }
}

removed {
  from = vault_generic_endpoint.int_cluster_config

  lifecycle {
    destroy = false
  }
}

removed {
  from = vault_generic_endpoint.pki_int_acme_tune

  lifecycle {
    destroy = false
  }
}
