#!/usr/bin/env bash
# Fail if the shipped binary's package graph links a forbidden dependency:
# telemetry SDKs or exporters, gRPC, managed-cloud SDKs, or the deprecated
# github.com/docker/docker module (replaced by github.com/moby/moby/*).
#
# The OpenTelemetry API packages (go.opentelemetry.io/otel, /trace, /metric,
# /log) and otelhttp are linked through github.com/moby/moby/client. Without
# an SDK they are no-op: no span, metric or log record leaves the process.
# This check keeps it that way.
set -euo pipefail

MAIN_PKG="${MAIN_PKG:-./cmd/previewd}"

deny_regex='^(go\.opentelemetry\.io/otel/sdk|go\.opentelemetry\.io/otel/exporters|go\.opentelemetry\.io/proto/otlp|google\.golang\.org/grpc|github\.com/aws/|cloud\.google\.com/go|google\.golang\.org/api|github\.com/Azure/azure-sdk-for-go|github\.com/docker/docker)(/|$)'

# Same build constraints as scripts/build.sh. Capture first so a go list
# failure aborts instead of yielding an empty, passing graph.
deps="$(CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go list -tags netgo -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' "${MAIN_PKG}")"

if [[ -z "${deps}" ]]; then
  echo "FATAL: empty dependency graph for ${MAIN_PKG}" >&2
  exit 1
fi

violations="$(grep -E "${deny_regex}" <<<"${deps}" || true)"
if [[ -n "${violations}" ]]; then
  echo "FATAL: forbidden packages linked into ${MAIN_PKG}:" >&2
  echo "${violations}" >&2
  exit 1
fi

echo "airgap-check: $(wc -l <<<"${deps}") non-std packages, none forbidden"
