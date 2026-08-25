# VAULT_TOKEN is read from the environment and vault_addr is supplied through
# TF_VAR_vault_addr by scripts/bootstrap.sh. The provider normally creates a limited child token,
# which would require granting auth/token/create. The bootstrap script already
# supplies a short-lived, non-renewable, policy-scoped token, so use it directly
# and keep token-minting authority out of the Terraform policy.
provider "vault" {
  address          = var.vault_addr
  skip_child_token = true
}
