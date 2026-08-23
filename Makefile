SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help
COMPOSE_ENV_FILE := $(if $(wildcard .env),.env,.env.example)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n",$$1,$$2}'

.PHONY: env
env: ## Create .env from .env.example if it does not exist
	@test -f .env || cp .env.example .env

.PHONY: prepare-dev-tls
prepare-dev-tls: ## Generate the local-only TLS certificate used by the Vault ACME endpoint
	./scripts/prepare-dev-tls.sh

.PHONY: up
up: env prepare-dev-tls ## Start the core stack
	docker compose up -d
	@$(MAKE) status

.PHONY: down
down: ## Stop core, observability, chaos, and optional Wazuh services
	docker compose -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml \
	  --profile app --profile tools --profile chaos --profile wazuh down --remove-orphans

.PHONY: clean
clean: ## Stop the stack and wipe all local state
	docker compose --env-file $(COMPOSE_ENV_FILE) \
	  -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml \
	  --profile app --profile tools --profile chaos --profile wazuh down -v --remove-orphans
	rm -rf .data
	rm -f terraform/bootstrap/terraform.tfstate terraform/bootstrap/terraform.tfstate.backup

.PHONY: status
status: ## Show container status and wait for Vault health
	docker compose ps
	@source scripts/lib/wait_for.sh && wait_for_http "http://localhost:$${VAULT_PORT:-8200}/v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204" 60 '^20[04]$$'

.PHONY: logs
logs: ## Tail logs for all services
	docker compose logs -f --tail=100

.PHONY: lint
lint: ## Run all linters (shellcheck, terraform fmt/validate, golangci-lint, hadolint)
	@echo "── shellcheck ──"; if command -v shellcheck >/dev/null; then shellcheck scripts/*.sh scripts/lib/*.sh; else echo "shellcheck not installed, skipping"; fi
	@echo "── terraform ──"; if command -v terraform >/dev/null; then terraform fmt -check -recursive terraform/ && (cd terraform/bootstrap && terraform init -backend=false -input=false >/dev/null && terraform validate); else echo "terraform not installed, skipping"; fi
	@echo "── golangci-lint ──"; \
	for svc in demo-api revocation-probe truststore-drift-agent; do \
	  if command -v golangci-lint >/dev/null; then (cd services/$$svc && golangci-lint run) || exit; else echo "golangci-lint not installed, skipping $$svc"; fi; \
	done
	@echo "── hadolint ──"; \
	for df in services/demo-api/Dockerfile services/revocation-probe/Dockerfile services/truststore-drift-agent/Dockerfile observability/webhook-logger/Dockerfile; do \
	  if command -v hadolint >/dev/null; then hadolint $$df || exit; else echo "hadolint not installed, skipping $$df"; fi; \
	done

# ── Phase 1: Terraform / bootstrap ────────────────────────────────────────

.PHONY: bootstrap
bootstrap: up ## Full bootstrap: start stack, init Vault, terraform apply
	./scripts/bootstrap.sh

.PHONY: tf-init
tf-init: ## terraform init in terraform/bootstrap
	cd terraform/bootstrap && terraform init -input=false

.PHONY: tf-apply
tf-apply: ## terraform apply in terraform/bootstrap
	cd terraform/bootstrap && terraform apply -auto-approve -input=false

.PHONY: tf-destroy
tf-destroy: ## terraform destroy in terraform/bootstrap
	cd terraform/bootstrap && terraform destroy -auto-approve -input=false

.PHONY: ca-chain
ca-chain: ## Export the pki_int CA chain to .data/ca_chain.pem for host-side curl
	@mkdir -p .data
	curl -s "http://localhost:$${VAULT_PORT:-8200}/v1/pki_int/ca_chain" -o .data/ca_chain.pem
	@test -s .data/ca_chain.pem && echo "wrote .data/ca_chain.pem" || (echo "ca-chain: empty response" >&2; exit 1)

# ── Phase 2: ACME / Traefik / demo-api ─────────────────────────────────────

.PHONY: demo-api-logs
demo-api-logs: ## Tail demo-api logs
	docker compose logs -f --tail=100 demo-api

# ── Phase 3: revocation-probe ──────────────────────────────────────────────

.PHONY: demo-revoke
demo-revoke: ## Run one probe cycle and pretty-print the detection table
	./scripts/demo-revoke.sh

.PHONY: attestation-key
attestation-key: ## Create an ignored Ed25519 keypair for signed local assurance reports
	./scripts/generate-attestation-key.sh

.PHONY: chaos-sweep
chaos-sweep: ## Sweep injected OCSP-path latency; writes docs/benchmarks/data/chaos-*.csv
	./scripts/chaos.sh

# ── Phase 4: observability & Wazuh ─────────────────────────────────────────

.PHONY: up-full
up-full: env prepare-dev-tls truststore-baseline ## Start core + observability (Prometheus/Grafana/Alertmanager)
	./scripts/gen-slack-url-file.sh
	docker compose -f docker-compose.yml -f docker-compose.observability.yml --profile app up -d
	@$(MAKE) status

.PHONY: up-wazuh
up-wazuh: env prepare-dev-tls ## Start core + observability + Wazuh (profile: wazuh; ~4GB RAM)
	./scripts/gen-slack-url-file.sh
	docker compose -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml --profile app --profile wazuh up -d
	@$(MAKE) status

.PHONY: wazuh-logtest
wazuh-logtest: env ## Validate the revocation audit fixture against Wazuh rule 100101
	./scripts/wazuh-logtest.sh

.PHONY: truststore-drift-demo
truststore-drift-demo: ## Install a synthetic rogue CA on the host and show truststore-drift-agent detect it
	./scripts/truststore-drift-demo.sh

.PHONY: truststore-baseline
truststore-baseline: ## Create a demo signed trust policy for the Prometheus exporter
	@mkdir -p .data/truststore/extra-cas .data/truststore/published .data/truststore/signer
	docker compose run --rm -T truststore-drift-agent baseline \
	  -o /data/published/baseline.json \
	  --private-key /data/signer/baseline.key \
	  --public-key /data/published/baseline.pub

# ── Phase 5: CI / supply chain ─────────────────────────────────────────────

.PHONY: test
test: ## Run unit tests for all Go services
	(cd services/demo-api && go test ./... -race) && \
	(cd services/revocation-probe && go test ./... -race) && \
	(cd services/truststore-drift-agent && go test ./... -race)

.PHONY: test-integration
test-integration: ## Run the integration test (requires make bootstrap first)
	@test -s .data/last-cycle.json || (echo "missing .data/last-cycle.json; run 'make demo-revoke' first" >&2; exit 1)
	@mkdir -p services/truststore-drift-agent/bin
	cd services/truststore-drift-agent && go build -o bin/truststore-drift-agent .
	cd tests/integration && PROBE_REPORT=../../.data/last-cycle.json \
	  TRUSTSTORE_AGENT_BIN=../../services/truststore-drift-agent/bin/truststore-drift-agent \
	  go test -tags=integration ./... -v

.PHONY: scan
scan: ## Run trivy + gitleaks locally
	@if command -v gitleaks >/dev/null; then gitleaks detect --no-git=false; else echo "gitleaks not installed, skipping"; fi
	@if command -v trivy >/dev/null; then trivy fs .; else echo "trivy not installed, skipping"; fi

.PHONY: diagrams
diagrams: ## Regenerate docs/images/architecture.svg from the D2 source
	d2 docs/diagrams/architecture.d2 docs/images/architecture.svg
