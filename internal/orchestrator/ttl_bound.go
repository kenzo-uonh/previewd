//go:build !e2e

package orchestrator

import "time"

// minEnvTTL is the shortest TTL NewReconciler accepts. Only an e2e build
// (ttl_bound_e2e.go) lowers it, with config's floor.
const minEnvTTL = time.Hour
