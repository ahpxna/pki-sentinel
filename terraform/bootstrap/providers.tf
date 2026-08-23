# VAULT_ADDR and VAULT_TOKEN are read from the environment (see
# scripts/bootstrap.sh). The provider normally creates a limited child token,
# which would require granting auth/token/create. The bootstrap script already
# supplies a short-lived, non-renewable, policy-scoped token, so use it directly
# and keep token-minting authority out of the Terraform policy.
provider "vault" {
  skip_child_token = true
}
