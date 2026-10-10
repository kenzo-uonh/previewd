//go:build e2e

package config

import "time"

// Floors of an e2e build: the short-TTL E2E scenario expires an environment
// within seconds. Never in a release build (scripts/build.sh sets no e2e
// tag; scripts/verify-e2e.sh checks the release binary lacks TestOnlyBounds).
const (
	minEnvTTL        = time.Second
	minPruneInterval = time.Second
)

// TestOnlyBounds is logged as an error at every start of an e2e build.
const TestOnlyBounds = "previewd-e2e-test-only-bounds: PREVIEWD_ENV_TTL and PREVIEWD_PRUNE_INTERVAL accept 1s"
