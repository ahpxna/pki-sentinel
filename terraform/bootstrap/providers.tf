# VAULT_ADDR and VAULT_TOKEN are read from the environment (see scripts/bootstrap.sh).
# Never hardcode a token in a .tf file.
provider "vault" {}
