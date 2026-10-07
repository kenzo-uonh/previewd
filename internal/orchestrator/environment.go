package orchestrator

import (
	"context"
	"errors"
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
	ID     string
	Image  string
	Port   int
	Domain string
	// SecretsDir is the host directory, on ramfs, holding this environment's
	// staged secrets. It is bind-mounted read-only; secret values never travel
	// through the Engine.
	SecretsDir string
}

// SecretStager stages an environment's secrets on memory-backed host storage
// and returns the directory to bind-mount read-only. Remove is idempotent.
type SecretStager interface {
	Stage(envID string, secrets map[string]string) (string, error)
	Remove(envID string) error
}

// Teardown destroys the environment's Docker resources, then its staged
// secrets. Secrets are removed even if Docker teardown fails.
func Teardown(ctx context.Context, engine Engine, stager SecretStager, envID string) error {
	var errs []error
	if err := engine.Destroy(ctx, envID); err != nil {
		errs = append(errs, fmt.Errorf("destroy environment %s: %w", envID, err))
	}
	if err := stager.Remove(envID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ProcessJob executes the end-to-end lifecycle for an EaaS environment.
func ProcessJob(ctx context.Context, job Job, cfg *config.Config, db *store.Store, engine Engine, injector *secrets.Injector, stager SecretStager) error {
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

	secretsDir, err := stager.Stage(job.EnvID, injector.GetSecrets())
	if err != nil {
		_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{ID: job.EnvID, Status: "failed"})
		return fmt.Errorf("secret staging step failed: %w", err)
	}

	env := Environment{
		ID:         job.EnvID,
		Image:      tag,
		Port:       8080,
		Domain:     cfg.TraefikDomain,
		SecretsDir: secretsDir,
	}
	if err := engine.Deploy(ctx, env); err != nil {
		err = fmt.Errorf("deploy step failed: %w", err)
		if rmErr := stager.Remove(job.EnvID); rmErr != nil {
			err = errors.Join(err, rmErr)
		}
		_ = db.UpsertEnvironment(ctx, store.EnvironmentRecord{ID: job.EnvID, Status: "failed"})
		return err
	}

	return db.UpsertEnvironment(ctx, store.EnvironmentRecord{
		ID:        job.EnvID,
		PRNumber:  job.PRNumber,
		Status:    "running",
		CreatedAt: time.Now().UTC(),
	})
}
