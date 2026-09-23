package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kenzo-uonh/previewd/internal/api"
	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

func processJob(ctx context.Context, job orchestrator.Job, db *store.Store, engine orchestrator.Engine) error {
	buildDir := fmt.Sprintf("/tmp/previewd-builds/%s", job.EnvID)
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

	env := orchestrator.Environment{
		ID:      job.EnvID,
		Image:   tag,
		Port:    8080,
		Secrets: map[string]string{},
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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("Configuration initialization failure", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Info("Previewd EaaS Agent - Starting...",
		"port", cfg.APIPort,
		"domain", cfg.TraefikDomain,
		"docker_host", cfg.DockerHost,
	)

	db, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		logger.Error("Database initialization failure", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database gracefully", "error", err)
		}
	}()

	engine, err := orchestrator.NewDockerEngine()
	if err != nil {
		logger.Error("Docker engine initialization failure", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			logger.Error("Failed to close Docker engine", "error", err)
		}
	}()

	pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
	defer pingCancel()

	if err := engine.Ping(pingCtx); err != nil {
		logger.Error("Docker daemon unreachable", "error", err)
		os.Exit(1)
	}

	pool := orchestrator.NewWorkerPool(10, logger)
	pool.Start(ctx, func(jobCtx context.Context, job orchestrator.Job) error {
		return processJob(jobCtx, job, db, engine)
	})

	apiServer := api.NewServer(logger, cfg, db, engine, pool)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.APIPort),
		Handler:           apiServer.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("Ingress HTTP server running", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server crash", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("Shutdown signal received, draining...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server graceful shutdown failed", "error", err)
	}

	logger.Info("Agent exited cleanly.")
}
