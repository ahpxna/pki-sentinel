package main

# Deny any vault_pki_secret_backend_role with max_ttl_seconds greater than
# 90 days. Short-lived certificates are this project's primary revocation
# control (see docs/adr/0003-short-lived-certs-over-revocation.md) — a role
# that grants long-lived leaves undermines that control regardless of how
# well revocation itself is enforced.

max_allowed_seconds := 90 * 24 * 3600

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	max_ttl := seconds(object.get(after, "max_ttl", object.get(after, "max_ttl_seconds", "0")))
	max_ttl > max_allowed_seconds
	msg := sprintf("role %q: max_ttl=%v exceeds the 90-day policy limit", [after.name, max_ttl])
}
