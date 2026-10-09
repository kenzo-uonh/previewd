//go:build !e2e

package config

import "time"

// Floors of PREVIEWD_ENV_TTL and PREVIEWD_PRUNE_INTERVAL. Only an e2e build
// (bounds_e2e.go, the short-TTL E2E scenario) lowers them; a release build
// never carries the e2e tag (scripts/build.sh).
const (
	minEnvTTL        = time.Hour
	minPruneInterval = time.Minute
)

// TestOnlyBounds describes the lowered floors of an e2e build; "" in a
// release build. main logs it as an error at every start.
const TestOnlyBounds = ""
