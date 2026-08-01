variable "pki_domain" {
  description = "Internal DNS domain for issued certificates."
  type        = string
  default     = "internal"
}

variable "org_name" {
  description = "Organization name used in CA subjects."
  type        = string
  default     = "PKI Sentinel Demo"
}

variable "vault_public_addr" {
  description = "Address Vault is reachable at from clients, used to construct AIA/CRL/OCSP URLs."
  type        = string
  default     = "http://localhost:8200"
}

variable "root_ttl_hours" {
  description = "Root CA max TTL, in hours."
  type        = number
  default     = 87600 # 10 years
}

variable "int_ttl_hours" {
  description = "Intermediate CA max TTL, in hours."
  type        = number
  default     = 8760 # 1 year
}

variable "leaf_max_ttl_hours" {
  description = "Maximum TTL for leaf certificates issued by the server/client roles."
  type        = number
  default     = 24
}
