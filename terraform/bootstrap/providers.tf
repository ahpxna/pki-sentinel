# VAULT_ADDR and VAULT_TOKEN are read from the environment (see scripts/bootstrap.sh).
# Tokens must not be stored in Terraform source files.
provider "vault" {}
