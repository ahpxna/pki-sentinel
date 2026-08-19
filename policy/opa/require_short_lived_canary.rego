package main

# The `canary` role exists specifically so revoked canaries expire out of
# the CRL quickly (see terraform/bootstrap/roles.tf). Deny any change that
# grows its max_ttl beyond 30 minutes.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	after.name == "canary"
	max_ttl := seconds(after.max_ttl)
	max_ttl > 1800
	msg := sprintf("canary role: max_ttl=%vs exceeds the 30-minute policy limit", [max_ttl])
}
