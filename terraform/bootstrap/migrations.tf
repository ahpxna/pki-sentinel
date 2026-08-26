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

# The persistent Terraform AppRole must not own the policy that authorizes it.
# Bootstrap installs that policy with a one-shot administrative credential;
# retain it in Vault while removing the legacy Terraform state address.
removed {
  from = vault_policy.terraform_bootstrap

  lifecycle {
    destroy = false
  }
}
