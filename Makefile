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
lint: ## Run all linters (placeholder in Phase 0)
	@echo "lint: nothing to check yet (Phase 0)"
