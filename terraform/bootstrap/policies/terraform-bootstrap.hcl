# The persistent Terraform AppRole manages only day-2 PKI and KV settings. A
# separate short-lived bootstrap-admin token creates mounts, auth methods,
# policies, audit devices, and AppRoles; keeping those powers out of this
# policy prevents a stolen AppRole from rewriting its own authority.
path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/mounts/pki_root" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "sys/mounts/pki_int" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

path "sys/mounts/kv" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

# This endpoint exposes mount metadata needed by the provider. It does not
# grant access to arbitrary secrets.
path "sys/internal/ui/mounts/*" {
  capabilities = ["read"]
}
path "pki_root/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki_int/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
