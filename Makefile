SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n",$$1,$$2}'

.PHONY: env
env: ## Create .env from .env.example if it does not exist
	@test -f .env || cp .env.example .env

.PHONY: up
up: env ## Start the core stack
	docker compose up -d
	@$(MAKE) status

.PHONY: down
down: ## Stop the core stack
	docker compose down

.PHONY: clean
clean: ## Stop the stack and wipe all local state
	docker compose down -v
	rm -rf .data

.PHONY: status
status: ## Show container status and wait for Vault health
	docker compose ps
	@source scripts/lib/wait_for.sh && wait_for_http "http://localhost:$${VAULT_PORT:-8200}/v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204" 60 '^(2|3|0)[0-9][0-9]$$'

.PHONY: logs
logs: ## Tail logs for all services
	docker compose logs -f --tail=100

.PHONY: lint
lint: ## Run all linters (shellcheck, terraform fmt/validate, golangci-lint, hadolint)
	@echo "── shellcheck ──"; command -v shellcheck >/dev/null && shellcheck scripts/*.sh scripts/lib/*.sh || echo "shellcheck not installed, skipping"
	@echo "── terraform fmt -check ──"; command -v terraform >/dev/null && terraform fmt -check -recursive terraform/ || echo "terraform not installed, skipping"
	@echo "── golangci-lint ──"; \
	for svc in demo-api revocation-probe truststore-drift-agent; do \
	  command -v golangci-lint >/dev/null && (cd services/$$svc && golangci-lint run) || echo "golangci-lint not installed, skipping $$svc"; \
	done
	@echo "── hadolint ──"; \
	for df in services/demo-api/Dockerfile services/revocation-probe/Dockerfile services/truststore-drift-agent/Dockerfile observability/webhook-logger/Dockerfile; do \
	  command -v hadolint >/dev/null && hadolint $$df || echo "hadolint not installed, skipping $$df"; \
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

.PHONY: chaos-sweep
chaos-sweep: ## Sweep injected OCSP-path latency; writes docs/benchmarks/data/chaos-*.csv
	./scripts/chaos.sh

# ── Phase 4: observability & Wazuh ─────────────────────────────────────────

.PHONY: up-full
up-full: env ## Start core + observability (Prometheus/Grafana/Alertmanager)
	./scripts/gen-slack-url-file.sh
	docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d
	@$(MAKE) status

.PHONY: up-wazuh
up-wazuh: env ## Start core + observability + Wazuh (profile: wazuh; ~4GB RAM)
	./scripts/gen-slack-url-file.sh
	docker compose -f docker-compose.yml -f docker-compose.observability.yml -f docker-compose.wazuh.yml --profile wazuh up -d
	@$(MAKE) status

.PHONY: truststore-drift-demo
truststore-drift-demo: ## Install a synthetic rogue CA on the host and show truststore-drift-agent detect it
	./scripts/truststore-drift-demo.sh

# ── Phase 5: CI / supply chain ─────────────────────────────────────────────

.PHONY: test
test: ## Run unit tests for all Go services
	(cd services/demo-api && go test ./... -race) && \
	(cd services/revocation-probe && go test ./... -race) && \
	(cd services/truststore-drift-agent && go test ./... -race)

.PHONY: test-integration
test-integration: ## Run the integration test (requires make bootstrap first)
	go test -tags=integration ./tests/integration/... -v

.PHONY: scan
scan: ## Run trivy + gitleaks locally
	gitleaks detect --no-git=false || true
	trivy fs . || true

.PHONY: diagrams
diagrams: ## Regenerate docs/images/architecture.svg from the D2 source
	d2 docs/diagrams/architecture.d2 docs/images/architecture.svg
