package main

# The intermediate PKI config_urls resource is mandatory in the post-plan
# state and must publish at least one OCSP responder. The offline-style root CA
# intentionally has no responder because it does not issue leaf certificates.

deny contains msg if {
	resource := input.resource_changes[_]
	resource.address == "vault_pki_secret_backend_config_urls.int"
	resource.change.after == null
	msg := sprintf("%s: required OCSP config must not be deleted", [resource.address])
}

deny contains msg if {
	resource := input.resource_changes[_]
	resource.address == "vault_pki_secret_backend_config_urls.int"
	after := resource.change.after
	after != null
	ocsp_servers := object.get(after, "ocsp_servers", [])
	count(ocsp_servers) == 0
	msg := sprintf("%s: ocsp_servers must not be empty", [resource.address])
}
