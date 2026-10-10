.PHONY: all build run dev clean fmt vet lint test sec deps deps-check vendor-check check verify airgap-check fmt-check repomix vuln docker-up docker-down help e2e verify-buildkit airgap-scan store-fixture-v2 semgrep release test-packages

APP_NAME    := previewd
BIN_DIR     := bin
MAIN_PKG    := ./cmd/$(APP_NAME)
GOPATH_BIN  := $(shell go env GOPATH)/bin

# Inject build metadata
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Dependency gate used by `check`: deps-check (module cache, networked) or
# vendor-check (vendor/ only, air-gapped).
DEPS_GATE   ?= deps-check
# Vulnerability database. Air-gapped: GOVULNDB=file:///path/to/vulndb
GOVULNDB    ?= https://vuln.go.dev # airgap:allow overridable default; air-gapped hosts pass GOVULNDB=file:///... (README)
# Fixed rapid seed for the deterministic gate (make check); never 0 (= random)
RAPID_SEED  ?= 1
# Deep verification budgets (make verify, random rapid seed)
RAPID_CHECKS ?= 10000
FUZZTIME    ?= 60s
# Package version: VERSION without its leading v when it starts with a
# digit (a release tag), 1.0.0 otherwise (an untagged commit hash or "dev").
PKG_VERSION ?= $(or $(shell echo '$(VERSION)' | sed -n 's/^v\{0,1\}\([0-9][0-9A-Za-z.+~-]*\)$$/\1/p'),1.0.0)
DIST_DIR    := dist

# Default target
.DEFAULT_GOAL := help
all: check build

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development & Quality Checks

check: $(DEPS_GATE) fmt-check vet lint sec vuln airgap-check airgap-scan test ## Run all verification checks and test suite (deterministic gate)

verify: ## Deep verification: rapid PBT (RAPID_CHECKS=10000) + every native fuzz target (FUZZTIME per target)
	@chmod +x scripts/verify.sh scripts/rapid-packages.sh
	@RAPID_CHECKS=$(RAPID_CHECKS) FUZZTIME=$(FUZZTIME) ./scripts/verify.sh

build: ## Compile a statically linked binary using the build script
	@echo "Compiling statically linked binary ($(VERSION))..."
	@chmod +x scripts/build.sh
	@VERSION=$(VERSION) ./scripts/build.sh

e2e: ## Run end-to-end operational verification
	@echo "Executing air-gapped E2E test suite..."
	@chmod +x scripts/verify-e2e.sh
	@./scripts/verify-e2e.sh

verify-buildkit: ## Probe the local engine's BuildKit isolation with previewd's exact /build request (E0; evidence in build/reports)
	@chmod +x scripts/verify-buildkit.sh
	@./scripts/verify-buildkit.sh

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
	@files="$$(find . -name '*.go' -not -path './vendor/*' -not -path './.git/*' -print)"; \
	unformatted="$$(gofmt -l $$files)"; \
	test -z "$$unformatted" || { echo "Unformatted files exist. Run 'make fmt':"; echo "$$unformatted"; exit 1; }

vet: ## Run standard go vet static analysis
	@echo "Running standard static analysis..."
	go vet ./...

lint: ## Run golangci-lint static checks
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || $(GOPATH_BIN)/golangci-lint run ./...

test: ## Execute the unit test suite (rapid packages use the fixed RAPID_SEED)
	@echo "Executing test suite..."
	@chmod +x scripts/test.sh scripts/rapid-packages.sh
	@RAPID_SEED=$(RAPID_SEED) ./scripts/test.sh

store-fixture-v2: ## Write internal/store/testdata/schema-v2-modernc.{sqlite,json} with the shipped driver (once; commit both files)
	CGO_ENABLED=0 PREVIEWD_WRITE_STORE_FIXTURE=1 go test -tags storefixture -count=1 -run '^TestWriteSchemaV2Fixture$$' -v ./internal/store/

airgap-scan: ## Static air-gap scan of source, deployments and specs (fails on LOW and above), after its own regression tests
	@echo "Running air-gap scanner self-tests..."
	@python3 -I -B scripts/airgap_scan_test.py
	@echo "Scanning source, deployment files and specs..."
	@python3 -I -B scripts/airgap_scan.py . --fail-on low

airgap-check: ## Fail if the binary links telemetry SDKs/exporters, gRPC, cloud SDKs or docker/docker
	@chmod +x scripts/airgap-check.sh
	@./scripts/airgap-check.sh

# The CI's pinned Semgrep image, run offline (--network none); it must be
# loaded on the host (docker load), never pulled by this target. The scan
# fails closed: no per-rule timeout (a rule that timed out on a file did not
# scan it) and --strict (any warning fails).
SEMGREP_IMAGE ?= semgrep/semgrep:1.179.0@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b
SEMGREP_RULES := previewd-rules previewd-no-container-output

semgrep: ## Semgrep rule self-tests, then the scan, in the pinned image without network (as CI)
	@for r in $(SEMGREP_RULES); do \
		docker run --rm --pull never --network none -v "$(CURDIR):/src:ro" -w /src "$(SEMGREP_IMAGE)" \
			semgrep --test --metrics=off --disable-version-check --config ".semgrep/$$r.yaml" ".semgrep/$$r.go" || exit 1; \
	done
	@docker run --rm --pull never --network none -v "$(CURDIR):/src:ro" -w /src "$(SEMGREP_IMAGE)" \
		semgrep scan --metrics=off --disable-version-check --error --strict --timeout 0 $(foreach r,$(SEMGREP_RULES),--config .semgrep/$(r).yaml) .

# Packaging images, pinned by digest. Each runs with --network none: on an
# air-gapped builder, docker load them first.
NFPM_IMAGE         ?= goreleaser/nfpm:v2.43.0@sha256:929e1056ba69bf1da57791e851d210e9d6d4f528fede53a55bd43cf85674450c
PKG_TEST_DEB_IMAGE ?= ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
PKG_TEST_RPM_IMAGE ?= fedora:40@sha256:3c86d25fef9d2001712bc3d9b091fc40cf04be4767e48f1aa3b785bf58d300ed

release: build ## Package bin/previewd as deb and rpm into dist/ (nfpm.yaml, PKG_VERSION)
	@echo "Packaging previewd $(PKG_VERSION) (deb, rpm)..."
	@mkdir -p $(DIST_DIR)
	@rm -f $(DIST_DIR)/previewd*.deb $(DIST_DIR)/previewd*.rpm
	docker run --rm --network none -u "$$(id -u):$$(id -g)" -e VERSION=$(PKG_VERSION) \
		-v "$(CURDIR):/src:ro" -v "$(CURDIR)/$(DIST_DIR):/src/$(DIST_DIR)" -w /src "$(NFPM_IMAGE)" \
		package --config nfpm.yaml --packager deb --target $(DIST_DIR)/
	docker run --rm --network none -u "$$(id -u):$$(id -g)" -e VERSION=$(PKG_VERSION) \
		-v "$(CURDIR):/src:ro" -v "$(CURDIR)/$(DIST_DIR):/src/$(DIST_DIR)" -w /src "$(NFPM_IMAGE)" \
		package --config nfpm.yaml --packager rpm --target $(DIST_DIR)/

test-packages: release ## Install the deb (Ubuntu 24.04) and rpm (Fedora 40) in throwaway containers without network (install, reinstall), check user and files
	@echo "Installing the deb on $(PKG_TEST_DEB_IMAGE)..."
	docker run --rm --network none -v "$(CURDIR)/$(DIST_DIR):/dist:ro" \
		-v "$(CURDIR)/scripts/check-package-install.sh:/check.sh:ro" "$(PKG_TEST_DEB_IMAGE)" \
		sh -euc 'apt-get install -y -q /dist/previewd*.deb && apt-get install -y -q --reinstall /dist/previewd*.deb && sh /check.sh' # airgap:allow installs the local package file, --network none
	@echo "Installing the rpm on $(PKG_TEST_RPM_IMAGE)..."
	docker run --rm --network none -v "$(CURDIR)/$(DIST_DIR):/dist:ro" \
		-v "$(CURDIR)/scripts/check-package-install.sh:/check.sh:ro" "$(PKG_TEST_RPM_IMAGE)" \
		sh -euc 'dnf install -y -q --disablerepo="*" /dist/previewd*.rpm && dnf reinstall -y -q --disablerepo="*" /dist/previewd*.rpm && sh /check.sh' # airgap:allow installs the local package file, --network none

sec: ## Run gosec AST security scanner
	@echo "Running AST security scanner..."
	@which gosec > /dev/null 2>&1 && gosec -quiet -exclude-dir=.semgrep ./... || $(GOPATH_BIN)/gosec -quiet -exclude-dir=.semgrep ./...

vuln: ## Scan dependencies for known vulnerabilities
	@echo "Checking known vulnerabilities with govulncheck..."
	@which govulncheck > /dev/null 2>&1 || (echo "FATAL: govulncheck not found. Pre-provision in air-gapped env." && exit 1)
	@govulncheck -db "$(strip $(GOVULNDB))" ./... > vuln-report.txt 2>&1 || { cat vuln-report.txt; echo "FATAL: govulncheck failed (findings or unreachable database $(strip $(GOVULNDB)))"; exit 1; }

deps: ## Tidy and verify Go modules (mutates go.mod/go.sum)
	@echo "Tidying and verifying dependencies..."
	go mod tidy
	go mod verify

deps-check: ## Fail if go.mod/go.sum are untidy or module hashes mismatch (no mutation)
	@echo "Checking module tidiness and hashes..."
	go mod tidy -diff
	go mod verify

vendor-check: ## Fail if vendor/ is missing or inconsistent with go.mod (offline)
	@echo "Checking vendor/ consistency..."
	@test -f vendor/modules.txt || (echo "FATAL: vendor/modules.txt missing. Run 'go mod vendor' while networked." && exit 1)
	go list -mod=vendor -deps -test ./... > /dev/null

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
	rm -rf $(BIN_DIR) $(DIST_DIR) tmp build-errors.log repomix-output.* vuln-report.txt coverage.out
	go clean -testcache