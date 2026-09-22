package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
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

	logger.Info("SQLite store initialized successfully", "path", cfg.DBPath)

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

	logger.Info("Docker engine initialized and connected successfully")

	<-ctx.Done()
	logger.Info("Shutdown signal received, draining connections...")
}
