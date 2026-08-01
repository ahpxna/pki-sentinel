package main

# Deny if a pki_int config_urls resource has no ocsp_servers configured.
# Without an OCSP AIA entry, clients that DO attempt revocation checking
# have no responder URL to find in the first place.

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "vault_pki_secret_backend_config_urls"
	ocsp_servers := object.get(resource.change.after, "ocsp_servers", [])
	count(ocsp_servers) == 0
	msg := sprintf("%s: ocsp_servers must not be empty", [resource.address])
}
