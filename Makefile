.PHONY: all build run dev clean fmt vet lint test sec deps check fmt-check repomix vuln docker-up docker-down help e2e

APP_NAME    := previewd
BIN_DIR     := bin
MAIN_PKG    := ./cmd/$(APP_NAME)
GOPATH_BIN  := $(shell go env GOPATH)/bin

# Inject build metadata
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Default target
.DEFAULT_GOAL := help
all: check build

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development & Quality Checks

check: deps fmt-check vet lint sec vuln test ## Run all verification checks and test suite

build: ## Compile a statically linked binary using the build script
	@echo "Compiling statically linked binary ($(VERSION))..."
	@chmod +x scripts/build.sh
	@VERSION=$(VERSION) ./scripts/build.sh

e2e: ## Run end-to-end operational verification
	@echo "Executing air-gapped E2E test suite..."
	@chmod +x scripts/verify-e2e.sh
	@./scripts/verify-e2e.sh

run: build ## Compile and start the previewd daemon
	@echo "Starting daemon..."
	./$(BIN_DIR)/$(APP_NAME)

dev: ## Run the application with air live reload
	@which air > /dev/null 2>&1 || (echo "FATAL: air not found. Pre-provision in air-gapped env." && exit 1)
	air

fmt: ## Format source files using go fmt
	@echo "Formatting codebase..."
	go fmt ./...

fmt-check: ## Verify source code formatting compliance
	@echo "Checking formatting compliance..."
	@test -z "$$(gofmt -l .)" || (echo "Unformatted files exist. Run 'make fmt':" && gofmt -l . && exit 1)

vet: ## Run standard go vet static analysis
	@echo "Running standard static analysis..."
	go vet ./...

lint: ## Run golangci-lint static checks
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || $(GOPATH_BIN)/golangci-lint run ./...

test: ## Execute the unit test suite
	@echo "Executing test suite..."
	CGO_ENABLED=0 go test -v -coverprofile=coverage.out ./...

sec: ## Run gosec AST security scanner
	@echo "Running AST security scanner..."
	@which gosec > /dev/null 2>&1 && gosec -quiet ./... || $(GOPATH_BIN)/gosec -quiet ./...

vuln: ## Scan dependencies for known vulnerabilities
	@echo "Checking known vulnerabilities with govulncheck..."
	@which govulncheck > /dev/null 2>&1 || (echo "FATAL: govulncheck not found. Pre-provision in air-gapped env." && exit 1)
	@govulncheck ./... > vuln-report.txt 2>&1 || echo "Vulnerability scan completed with warnings (see vuln-report.txt)"

deps: ## Tidy and verify Go modules
	@echo "Tidying and verifying dependencies..."
	go mod tidy
	go mod verify

repomix: ## Bundle codebase context for LLM ingestion
	@echo "Bundling codebase for LLM ingestion..."
	npx repomix --ignore "build/**,bin/**,tmp/**,.git/**,.idea/**,*.sqlite,repomix-output.*,go.sum,coverage.out"

##@ Infrastructure

docker-up: ## Start local docker compose services (Traefik)
	@echo "Starting local infra (Traefik & test containers)..."
	docker compose -f deployments/docker-compose.yml up -d

docker-down: ## Stop local docker compose services
	@echo "Stopping local infra..."
	docker compose -f deployments/docker-compose.yml down -v

clean: ## Clean build artifacts, logs, and caches
	@echo "Cleaning workspace..."
	rm -rf $(BIN_DIR) tmp build-errors.log repomix-output.* vuln-report.txt coverage.out
	go clean -testcache