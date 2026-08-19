# Vault file audit device. Writes JSON audit entries to /vault/logs/audit.json.
# The container mount is defined in docker-compose.yml. The Wazuh decoder and
# rules under observability/wazuh parse this stream.
resource "vault_audit" "file" {
  type = "file"

  options = {
    file_path = "/vault/logs/audit.json"
  }
}
