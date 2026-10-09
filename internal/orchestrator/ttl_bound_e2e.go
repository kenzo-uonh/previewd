//go:build e2e

package orchestrator

import "time"

// minEnvTTL of an e2e build: the short-TTL E2E scenario (config.TestOnlyBounds).
const minEnvTTL = time.Second
