module github.com/pki-sentinel/pki-sentinel/services/revocation-probe

go 1.22

require (
	github.com/hashicorp/vault/api v1.14.0
	github.com/hashicorp/vault/api/auth/approle v0.7.0
	github.com/prometheus/client_golang v1.19.1
	golang.org/x/crypto v0.24.0
	github.com/google/uuid v1.6.0
	gopkg.in/yaml.v3 v3.0.1
)
