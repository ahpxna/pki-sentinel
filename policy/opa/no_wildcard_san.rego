package main

# Deny allow_glob_domains=true combined with allow_subdomains=true on a
# server role — this combination allows arbitrarily broad wildcard-shaped
# SANs to be issued, defeating the point of scoped, short-lived leaf certs.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_role"
	after := resource.change.after
	after.server_flag == true
	object.get(after, "allow_glob_domains", false) == true
	object.get(after, "allow_subdomains", false) == true
	msg := sprintf("role %q: allow_glob_domains + allow_subdomains together permit unbounded wildcard SANs", [after.name])
}
