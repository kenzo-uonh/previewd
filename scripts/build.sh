#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin

VERSION=${VERSION:-"dev"}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

LDFLAGS="-w -s -extldflags '-static' \
  -X 'main.Version=${VERSION}' \
  -X 'main.Commit=${COMMIT}' \
  -X 'main.BuildTime=${BUILD_TIME}'"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -a -tags netgo -ldflags "${LDFLAGS}" -o bin/previewd ./cmd/previewd

chmod +x bin/previewd