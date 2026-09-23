package orchestrator

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/secrets"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// Environment encapsulates the runtime parameters for an ephemeral stack.
type Environment struct {
	ID      string
	Image   string
	Port    int
	Domain  string
	Secrets map[string]string // Injected purely into memory; never written to SQLite or disk.
}

// ProcessJob executes the end-to-end lifecycle for an EaaS environment.
func ProcessJob(ctx context.Context, job Job, cfg *config.Config, db *store.Store, engine Engine, injector *secrets.Injector) error {
	// Exhaustive Teardown: Enforce clean state for re-entrant updates (ActionSynchronize).
	_ = engine.Destroy(ctx, job.EnvID)

	buildDir := fmt.Sprintf("/tmp/previewd-builds/%s", job.EnvID)

	// Enforce artifact cleanup constraint.
	defer func() {
		_ = os.RemoveAll(buildDir)
	}()

	_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{
		ID:        job.EnvID,
		PRNumber:  job.PRNumber,
		Status:    "building",
		CreatedAt: time.Now().UTC(),
	})

	if err := vcs.FetchRepository(ctx, job.CloneURL, job.Commit, buildDir); err != nil {
		_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{ID: job.EnvID, Status: "failed"})
		return fmt.Errorf("fetch step failed: %w", err)
	}

	if err := engine.ProvisionNetwork(ctx, job.EnvID); err != nil {
		_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{ID: job.EnvID, Status: "failed"})
		return fmt.Errorf("network step failed: %w", err)
	}

	tag := fmt.Sprintf("%s:latest", job.EnvID)
	if err := engine.Build(ctx, buildDir, tag); err != nil {
		_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{ID: job.EnvID, Status: "failed"})
		return fmt.Errorf("build step failed: %w", err)
	}

	env := Environment{
		ID:      job.EnvID,
		Image:   tag,
		Port:    8080,
		Domain:  cfg.TraefikDomain,
		Secrets: injector.GetSecrets(),
	}
	if err := engine.Deploy(ctx, env); err != nil {
		_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{ID: job.EnvID, Status: "failed"})
		return fmt.Errorf("deploy step failed: %w", err)
	}

	return db.UpsertEnvironment(ctx, store.EnvironmentRecord{
		ID:        job.EnvID,
		PRNumber:  job.PRNumber,
		Status:    "running",
		CreatedAt: time.Now().UTC(),
	})
}
