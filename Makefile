.PHONY: help build run test tidy fmt vet up down logs vendor-vue

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the server binary (frontend is already embedded)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/certtracker ./cmd/server

run: ## Run locally (expects DATABASE_URL in the environment)
	go run ./cmd/server

test: ## Run the unit tests
	go test ./...

tidy: ## Sync go.mod/go.sum
	go mod tidy

fmt: ## Format code
	go fmt ./...

vet: ## Static checks
	go vet ./...

up: ## Start the full stack (app + postgres) via docker compose
	docker compose up --build

down: ## Stop the stack
	docker compose down

logs: ## Tail app logs
	docker compose logs -f app

vendor-vue: ## Refresh the vendored Vue runtime (needs npm)
	npm pack vue@3 >/dev/null 2>&1 && \
	tar -xzf vue-*.tgz && \
	cp package/dist/vue.global.prod.js internal/web/static/vue.global.prod.js && \
	rm -rf package vue-*.tgz && \
	echo "vendored $$(head -2 internal/web/static/vue.global.prod.js | tail -1)"
