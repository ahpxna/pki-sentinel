package main

# Deny any live vault_pki_secret_backend_role whose maximum leaf TTL is
# missing, zero/non-positive, or greater than 90 days. Missing/zero must fail
# closed: Vault can otherwise fall back to a much larger system/backend TTL.

max_allowed_seconds := (90 * 24) * 3600

role_max_ttl(after) := raw if {
	raw := object.get(after, "max_ttl", object.get(after, "max_ttl_seconds", null))
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	after != null
	role_max_ttl(after) == null
	name := object.get(after, "name", resource.address)
	msg := sprintf("role %q: max_ttl must be explicitly configured", [name])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	after != null
	role_max_ttl(after) == ""
	name := object.get(after, "name", resource.address)
	msg := sprintf("role %q: max_ttl must not be empty", [name])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	after != null
	raw := role_max_ttl(after)
	raw != null
	max_ttl := seconds(raw)
	max_ttl <= 0
	name := object.get(after, "name", resource.address)
	msg := sprintf("role %q: max_ttl must be positive, got %v", [name, max_ttl])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	after != null
	raw := role_max_ttl(after)
	raw != null
	max_ttl := seconds(raw)
	max_ttl > max_allowed_seconds
	name := object.get(after, "name", resource.address)
	msg := sprintf("role %q: max_ttl=%v exceeds the 90-day policy limit", [name, max_ttl])
}
