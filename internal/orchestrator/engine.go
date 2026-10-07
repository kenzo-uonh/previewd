package orchestrator

import (
	"context"
	"io"
	"net/netip"
)

// Engine defines the strictly air-gapped orchestration contract.
type Engine interface {
	Ping(ctx context.Context) error
	Build(ctx context.Context, buildDir, tag string) error
	ProvisionNetwork(ctx context.Context, envID string) error
	// Deploy starts the environment and returns the address its route
	// document points to.
	Deploy(ctx context.Context, env Environment) (netip.AddrPort, error)
	Destroy(ctx context.Context, id string) error
	// Observe reports what the engine holds for every environment previewd
	// owns, including leftovers no job tracks.
	Observe(ctx context.Context) (map[string]EngineState, error)
	Logs(ctx context.Context, id string) (io.ReadCloser, error)
	Close() error
}
