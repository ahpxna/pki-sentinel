# Vault file audit device. Ships JSON audit entries to /vault/logs/audit.json
# (mounted into the container — see docker-compose.yml), which Wazuh's
# custom decoder (observability/wazuh/decoders/vault_audit.xml) and rules
# (observability/wazuh/rules/local_rules.xml) parse in Phase 4.
resource "vault_audit" "file" {
  type = "file"

  options = {
    file_path = "/vault/logs/audit.json"
  }
}
