package main

# Shared helper: parse a Vault-style duration string ("24h", "8760h",
# "1800s", or a bare number of seconds) into seconds. Vault's Terraform
# provider represents TTL fields as strings in most schema versions, but
# some fields (e.g. max_lease_ttl_seconds) are plain integers — this
# handles both so the policies below don't have to care which.
seconds(v) = n {
	is_number(v)
	n := v
}

seconds(v) = n {
	is_string(v)
	endswith(v, "h")
	hours := to_number(trim_suffix(v, "h"))
	n := hours * 3600
}

seconds(v) = n {
	is_string(v)
	endswith(v, "m")
	mins := to_number(trim_suffix(v, "m"))
	n := mins * 60
}

seconds(v) = n {
	is_string(v)
	endswith(v, "s")
	n := to_number(trim_suffix(v, "s"))
}

seconds(v) = n {
	is_string(v)
	not endswith(v, "h")
	not endswith(v, "m")
	not endswith(v, "s")
	n := to_number(v)
}
