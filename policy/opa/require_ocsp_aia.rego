package main

# Deny if the intermediate PKI config_urls resource has no ocsp_servers
# configured. The offline-style root CA does not issue leaf certificates and
# intentionally has no OCSP responder.
# Without an OCSP AIA entry, clients that DO attempt revocation checking
# have no responder URL to find in the first place.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.address == "vault_pki_secret_backend_config_urls.int"
	ocsp_servers := object.get(resource.change.after, "ocsp_servers", [])
	count(ocsp_servers) == 0
	msg := sprintf("%s: ocsp_servers must not be empty", [resource.address])
}
