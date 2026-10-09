package orchestrator

import (
	"context"
	"io"
	"net/netip"
)

// Engine defines the strictly air-gapped orchestration contract.
type Engine interface {
	Ping(ctx context.Context) error
	// Build builds spec.ContextTar with BuildKit, the network forced to
	// "none" for every RUN, no pull, no cache. It fails on any error the
	// daemon reports in the response stream: HTTP 200 is not success.
	Build(ctx context.Context, spec BuildSpec) error
	// BuildProbe builds the startup probe image with the request PR builds
	// get, and fails unless its RUN step found no network (VerifyBuildIsolation).
	BuildProbe(ctx context.Context, addr netip.AddrPort) error
	ProvisionNetwork(ctx context.Context, envID string) error
	// Deploy starts the environment and returns the address its route
	// document points to.
	Deploy(ctx context.Context, env Environment) (netip.AddrPort, error)
	Destroy(ctx context.Context, id string) error
	// Observe reports what the engine holds for every environment previewd
	// owns, including leftovers no job tracks.
	Observe(ctx context.Context) (map[string]EngineState, error)
	Logs(ctx context.Context, id string) (io.ReadCloser, error)
	// PruneImages removes every image previewd built (ownership labels)
	// whose environment is not in keep, and reports the bytes reclaimed. An
	// image a container still uses is kept (V1-I9).
	PruneImages(ctx context.Context, keep []string) (reclaimed int64, err error)
	// PruneBuildCache removes the daemon's unused build cache: no BuildKit
	// state of a build survives into another PR's (V1-I9, section 2.3).
	PruneBuildCache(ctx context.Context) (reclaimed int64, err error)
	// FreeDisk is the space left for unprivileged writers on the file
	// system of the engine's data root (the deploy's free-disk floor).
	FreeDisk(ctx context.Context) (int64, error)
	Close() error
}

// BuildSpec is one build. The context is a tar validated by
// PrepareBuildContext, never a host path. It carries no per-build memory,
// CPU or cgroup parent: BuildKit ignores them (D-V1-4); build bounds are
// daemon-level.
type BuildSpec struct {
	ContextTar io.Reader
	Tag        string
	EnvID      string
	JobID      int64
}
