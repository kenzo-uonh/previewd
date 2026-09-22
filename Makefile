.PHONY: all build run clean

APP_NAME := previewd
BIN_DIR := bin

all: build

build:
	@echo "Compiling statically linked binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o $(BIN_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

run: build
	@echo "Starting daemon..."
	./$(BIN_DIR)/$(APP_NAME)

clean:
	rm -rf $(BIN_DIR)