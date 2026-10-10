#!/usr/bin/env bash
# Print the import path of every package whose tests import
# pgregory.net/rapid, one per line.
#
# -rapid.* flags are registered only in test binaries that import rapid;
# passing them to any other package aborts with "flag provided but not
# defined". Callers use this list to scope those flags.
set -euo pipefail

# Capture first so a go list failure aborts instead of yielding an empty list.
listing="$(go list -f '{{.ImportPath}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' ./...)"
awk '{for (i = 2; i <= NF; i++) if ($i == "pgregory.net/rapid") {print $1; next}}' <<<"${listing}"
