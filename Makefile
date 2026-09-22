.PHONY: all build run dev clean fmt vet lint test sec deps check fmt-check

APP_NAME := previewd
BIN_DIR := bin
MAIN_PKG := ./cmd/$(APP_NAME)
GOPATH_BIN := $(shell go env GOPATH)/bin

all: check build

check: deps fmt-check vet lint sec test

build:
	@echo "Compiling statically linked binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -extldflags '-static'" -o $(BIN_DIR)/$(APP_NAME) $(MAIN_PKG)

run: build
	@echo "Starting daemon..."
	./$(BIN_DIR)/$(APP_NAME)

dev:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/air-verse/air@latest)
	air

fmt:
	@echo "Formatting codebase..."
	go fmt ./...

fmt-check:
	@echo "Checking formatting compliance..."
	@test -z "$$(gofmt -l .)" || (echo "Unformatted files exist. Run 'make fmt':" && gofmt -l . && exit 1)

vet:
	@echo "Running standard static analysis..."
	go vet ./...

lint:
	@echo "Running golangci-lint..."
	$(GOPATH_BIN)/golangci-lint run ./...

test:
	@echo "Executing test suite..."
	go test -v -cover ./...

sec:
	@echo "Running AST security scanner..."
	$(GOPATH_BIN)/gosec -quiet ./...

deps:
	@echo "Tidying and verifying dependencies..."
	go mod tidy
	go mod verify

clean:
	@echo "Cleaning workspace..."
	rm -rf $(BIN_DIR) tmp build-errors.log
	go clean -testcache