package orchestrator

import (
	"context"
	"io"
)

// Engine defines the strictly air-gapped orchestration contract.
type Engine interface {
	Ping(ctx context.Context) error
	Build(ctx context.Context, buildDir, tag string) error
	ProvisionNetwork(ctx context.Context, envID string) error
	Deploy(ctx context.Context, env Environment) error
	Destroy(ctx context.Context, id string) error
	Logs(ctx context.Context, id string) (io.ReadCloser, error)
	Close() error
}
