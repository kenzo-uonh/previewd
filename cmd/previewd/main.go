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
	"github.com/kenzo-uonh/previewd/internal/hardening"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/secrets"
	"github.com/kenzo-uonh/previewd/internal/store"
)

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

	// Lock memory before any secret is read into it.
	if err := hardening.LockMemory(); err != nil {
		if !cfg.AllowUnlockedMemory {
			logger.Error("Process memory lock refused", "error", err)
			os.Exit(1)
		}
		logger.Error("Opt-in active: process memory not locked, secrets in memory can be swapped to disk",
			"opt_in", "PREVIEWD_ALLOW_UNLOCKED_MEMORY",
			"error", err,
		)
	}

	injector, err := secrets.NewInjector(cfg.SecretsPath)
	if err != nil {
		logger.Error("Secrets injector initialization failure", "error", err)
		os.Exit(1)
	}

	if cfg.AllowTmpfsSecrets {
		logger.Error("Opt-in active: secrets staged on tmpfs, whose pages can be swapped to disk",
			"opt_in", "PREVIEWD_ALLOW_TMPFS_SECRETS",
			"staging_dir", cfg.SecretsStagingDir,
		)
	}

	stager, err := secrets.NewStager(cfg.SecretsStagingDir, cfg.AllowTmpfsSecrets)
	if err != nil {
		logger.Error("Secret staging directory refused", "staging_dir", cfg.SecretsStagingDir, "error", err)
		os.Exit(1)
	}

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

	// Enforce bounded deployment concurrency based on configuration
	pool := orchestrator.NewWorkerPool(cfg.MaxConcurrentBuilds, logger)
	pool.Start(ctx, func(jobCtx context.Context, job orchestrator.Job) error {
		return orchestrator.ProcessJob(jobCtx, job, cfg, db, engine, injector, stager)
	})

	apiServer := api.NewServer(logger, cfg, db, engine, stager, pool)
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
