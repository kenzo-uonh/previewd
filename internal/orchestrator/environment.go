package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kenzo-uonh/previewd/internal/proxy"
)

// Environment encapsulates the runtime parameters for an ephemeral stack.
type Environment struct {
	ID     string
	Image  string
	Port   int
	Domain string
	// JobID is the deploy job that builds this version, recorded as an
	// ownership label so the startup sweep can match it to the database.
	JobID int64
	// SecretsDir is the host directory, on ramfs, holding this environment's
	// staged secrets. It is bind-mounted read-only; secret values never travel
	// through the Engine.
	SecretsDir string
}

// EngineState is what the engine holds for one environment.
type EngineState struct {
	Running      bool  // a container of the environment is running
	NetworkBound bool  // its internal network exists
	Containers   int   // containers owned by the environment, any state
	JobID        int64 // ownership label of the container; 0 if unknown
}

// SecretStager stages an environment's secrets on memory-backed host storage
// and returns the directory to bind-mount read-only. Remove is idempotent.
// List returns the environments with staged secrets.
type SecretStager interface {
	Stage(envID string, secrets map[string]string) (string, error)
	Remove(envID string) error
	List() ([]string, error)
}

// RoutePublisher writes and removes the route document of one environment
// in the directory the proxy's file provider watches. Remove is idempotent.
// Inventory lists the environments with a route document after deleting
// every other file the proxy could load.
type RoutePublisher interface {
	Publish(r proxy.Route) error
	Remove(envID string) error
	Inventory() (routes, removed []string, err error)
}

// cleanupTimeout bounds a rollback that runs after the job's context ended.
const cleanupTimeout = 2 * time.Minute

// Teardown removes the environment's route first, so the proxy stops sending
// traffic, then its Docker resources, then its staged secrets. Every step
// runs even if an earlier one fails; the errors are joined.
func Teardown(ctx context.Context, engine Engine, routes RoutePublisher, stager SecretStager, envID string) error {
	var errs []error
	if err := routes.Remove(envID); err != nil {
		errs = append(errs, err)
	}
	if err := engine.Destroy(ctx, envID); err != nil {
		errs = append(errs, fmt.Errorf("destroy environment %s: %w", envID, err))
	}
	if err := stager.Remove(envID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
