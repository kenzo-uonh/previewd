package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/kenzo-uonh/previewd/internal/api"
	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/hardening"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/proxy"
	"github.com/kenzo-uonh/previewd/internal/secrets"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	// appPort is the port every PR application listens on (MVP contract).
	appPort = 8080
	// startupSweepTimeout bounds the inventory, the sweep and the removal of
	// what the database does not keep.
	startupSweepTimeout = 5 * time.Minute
	// buildProbeTimeout bounds the startup build probe; defaultProbePort is
	// the probe's TCP port on the bridge gateway (discard: nothing should
	// listen, and nothing may answer).
	buildProbeTimeout = 3 * time.Minute
	defaultProbePort  = 9
	// freeDiskTimeout bounds the startup read of the free-disk floor.
	freeDiskTimeout = 10 * time.Second
	// activityReadInterval is how often Traefik's request counters are read;
	// activityFlushTick how often the tap looks for activity to write (each
	// environment is written at most once a minute whatever these are).
	activityReadInterval = 15 * time.Second
	activityFlushTick    = 5 * time.Second
)

func main() {
	if code, ran := subcommand(); ran {
		os.Exit(code)
	}
	logger := newLogger(os.Stdout)
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("Configuration initialization failure", "error", err)
		os.Exit(1)
	}

	if config.TestOnlyBounds != "" {
		logger.Error("Test-only build: never run it in production", "build", config.TestOnlyBounds)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Info("Previewd EaaS Agent - Starting...",
		"port", cfg.APIPort,
		"domain", cfg.TraefikDomain,
		"docker_host", cfg.DockerHost,
	)

	// No core file may ever hold a secret: refused unless verified, before
	// any secret is read (the unit also sets LimitCORE=0).
	if err := hardening.DisableCoreDumps(); err != nil {
		logger.Error("Core dump suppression refused", "error", err)
		os.Exit(1)
	}

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

	// The webhook HMAC key: a systemd credential, read once memory is
	// locked, held in memory only (never the environment, never a path).
	webhookSecret, err := secrets.WebhookSecret(cfg.WebhookSecretCredential)
	if err != nil {
		logger.Error("Webhook secret refused", "credential", cfg.WebhookSecretCredential, "error", err)
		os.Exit(1)
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

	routes, err := proxy.NewPublisher(cfg.RoutesDir)
	if err != nil {
		logger.Error("Routes directory refused", "routes_dir", cfg.RoutesDir, "error", err)
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

	engine, err := orchestrator.NewDockerEngine(cfg.TraefikContainer, orchestrator.Limits{
		MemoryBytes: cfg.ContainerMemoryMiB << 20,
		Pids:        cfg.ContainerPids,
	}, cfg.DockerDataRoot, hardening.FreeDiskBytes)
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

	// The proxy must never reach the Docker daemon: no socket, no Docker
	// provider. It only reads the route documents previewd writes.
	if err := engine.VerifyProxy(pingCtx); err != nil {
		logger.Error("Proxy container refused", "proxy_container", cfg.TraefikContainer, "error", err)
		os.Exit(1)
	}

	// Build isolation (V1 F2): every allowlisted base image is on the host
	// as its name:tag with the pinned digest, without ONBUILD triggers.
	// previewd never pulls.
	if err := engine.VerifyBaseImages(pingCtx, cfg.AllowedBaseImages); err != nil {
		logger.Error("Base images refused", "error", err)
		os.Exit(1)
	}
	logger.Info("Build preflight armed",
		"allowed_base_images", slices.Sorted(maps.Keys(cfg.AllowedBaseImages)),
		"max_build_context_bytes", cfg.MaxBuildContextBytes)
	if cfg.ComposeEnabled {
		// Sidecar images are the allowlisted ones, verified above.
		logger.Info("Compose sidecars enabled", "max_services", cfg.ComposeMaxServices)
	}

	// Free-disk floor (V1 F5, V1-I9): the data root must be measurable, or
	// no deploy could ever start. Below the floor the daemon still starts,
	// so teardowns and the prune loop can free space; builds are refused.
	diskCtx, diskCancel := context.WithTimeout(ctx, freeDiskTimeout)
	free, err := engine.FreeDisk(diskCtx)
	diskCancel()
	if err != nil {
		logger.Error("Free disk of the Docker data root unknown: refusing to start", "data_root", cfg.DockerDataRoot, "error", err)
		os.Exit(1)
	}
	if free < cfg.MinFreeDiskBytes {
		logger.Error("Free disk below the floor: builds are refused until space is freed",
			"free_bytes", free, "min_free_bytes", cfg.MinFreeDiskBytes)
	}
	logger.Info("Free-disk floor armed", "free_bytes", free, "min_free_bytes", cfg.MinFreeDiskBytes, "data_root", cfg.DockerDataRoot)

	// Startup build probe (V1 F2, E2b, D-V1-4), before the sweep and before
	// any worker: the request PR builds get must give its RUN step no
	// network, inside the bounded build cgroup, leaving nothing behind.
	probeAddr := cfg.BuildProbeAddr
	if !probeAddr.IsValid() {
		gw, err := engine.BridgeGateway(pingCtx)
		if err != nil {
			logger.Error("Build probe address unknown", "error", err)
			os.Exit(1)
		}
		probeAddr = netip.AddrPortFrom(gw, defaultProbePort)
	}
	isolation := orchestrator.BuildIsolation{Prober: engine, ProbeAddr: probeAddr, Unbounded: cfg.AllowUnboundedBuilds}
	if cfg.AllowUnboundedBuilds {
		logger.Error("Opt-in active: builds are not verified to run in a bounded cgroup (memory, swap, tasks, CPU)",
			"opt_in", "PREVIEWD_ALLOW_UNBOUNDED_BUILDS")
	} else {
		buildCgroup, err := hardening.NewBuildCgroup(cfg.BuildKitCgroup)
		if err != nil {
			logger.Error("Build cgroup refused", "build_cgroup", cfg.BuildKitCgroup, "error", err)
			os.Exit(1)
		}
		isolation.Cgroup = buildCgroup
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, buildProbeTimeout)
	err = orchestrator.VerifyBuildIsolation(probeCtx, isolation)
	probeCancel()
	if err != nil {
		logger.Error("Startup build probe failed: refusing to start", "probe_addr", probeAddr, "error", err)
		os.Exit(1)
	}
	logger.Info("Startup build probe passed", "probe_addr", probeAddr, "build_cgroup", cfg.BuildKitCgroup)

	// The forge: the deploy gate (V1 F1, D4) and the source fetch (H2,
	// V1-I11) of the one forge PREVIEWD_VCS_PROVIDER selects.
	vcsForge, err := newForge(cfg, db, logger)
	if err != nil {
		logger.Error("Forge refused", "provider", cfg.VCSProvider, "error", err)
		os.Exit(1)
	}

	reconciler, err := orchestrator.NewReconciler(orchestrator.ReconcilerConfig{
		Queue:                db,
		Engine:               engine,
		Routes:               routes,
		Stager:               stager,
		Secrets:              injector,
		Authorizer:           vcsForge.authorizer,
		Fetch:                vcsForge.fetch,
		Logger:               logger,
		Domain:               cfg.TraefikDomain,
		AppPort:              appPort,
		AllowedBaseImages:    cfg.AllowedBaseImages,
		MaxBuildContextBytes: cfg.MaxBuildContextBytes,
		MaxConcurrentBuilds:  cfg.MaxConcurrentBuilds,
		BuildTimeout:         cfg.BuildTimeout,
		RevalidateInterval:   cfg.RevalidateInterval,
		RevalidateGrace:      cfg.RevalidateGrace,
		Retention:            cfg.Retention,
		DeliveryMaxAge:       cfg.DeliveryMaxAge,
		PruneInterval:        cfg.PruneInterval,
		PruneBatch:           cfg.PruneBatch,
		MinFreeDiskBytes:     cfg.MinFreeDiskBytes,
		EnvTTL:               cfg.EnvTTL,
		DisableTTL:           cfg.EnvTTL == 0,
		Feedback:             vcsForge.feedback,
		PreviewScheme:        cfg.PreviewScheme,
		ComposeEnabled:       cfg.ComposeEnabled,
		ComposeMaxServices:   cfg.ComposeMaxServices,
	})
	if err != nil {
		logger.Error("Reconciler initialization failure", "error", err)
		os.Exit(1)
	}

	// StartupSweep before anything is served: the host is brought back to
	// what the database keeps, and no route document survives without it.
	sweepCtx, sweepCancel := context.WithTimeout(ctx, startupSweepTimeout)
	err = reconciler.Startup(sweepCtx)
	sweepCancel()
	if err != nil {
		logger.Error("Startup sweep failed: refusing to serve", "error", err)
		os.Exit(1)
	}

	// Build bounds (D-V1-4, V1-I12): builds share the daemon-level BuildKit
	// limits, so more than one at a time needs those limits scaled.
	if cfg.MaxConcurrentBuilds > 1 {
		logger.Warn("More than one build at a time: the BuildKit cgroup limits must be scaled for them",
			"max_concurrent_builds", cfg.MaxConcurrentBuilds, "build_cgroup", cfg.BuildKitCgroup)
	}
	logger.Info("Build bounds armed", "workers", cfg.Workers, "max_concurrent_builds", cfg.MaxConcurrentBuilds,
		"build_timeout", cfg.BuildTimeout)

	var background sync.WaitGroup
	background.Go(func() { reconciler.Run(ctx, cfg.Workers) })
	// Re-validation of every running environment (D-V1-5, V1-I4).
	background.Go(func() { reconciler.Revalidate(ctx) })
	logger.Info("Re-validation loop running", "interval", cfg.RevalidateInterval, "grace", cfg.RevalidateGrace)
	// Database maintenance (V1 F3): after the sweep, never before (the
	// store refuses), and only with V1-I7 in the handler (D2), which keeps
	// a pruned delivery from coming back as a new intent.
	background.Go(func() { reconciler.Maintain(ctx) })
	if cfg.EnvTTL == 0 {
		logger.Error("Opt-out active: environments never expire, PREVIEWD_ENV_TTL=0", "opt_out", "PREVIEWD_ENV_TTL")
	}
	logger.Info("Maintenance loop running", "interval", cfg.PruneInterval, "retention", cfg.Retention, "batch", cfg.PruneBatch,
		"env_ttl", cfg.EnvTTL)
	// Ingress activity sensing (V1.2 spec 3.3): Traefik's per-router request
	// counters, read on a timer, coalesced into at most one write per
	// environment per minute. Information for operators, not a control: a
	// proxy whose metrics cannot be read is logged, and nothing else changes.
	if cfg.ActivitySensing {
		tap, err := proxy.NewActivityTap(db, func(err error) bool { return errors.Is(err, store.ErrNoJob) }, logger)
		if err != nil {
			logger.Error("Activity tap refused", "error", err)
			os.Exit(1)
		}
		counters, err := proxy.NewTraefikMetrics(cfg.TraefikMetricsAddr, tap, logger)
		if err != nil {
			logger.Error("Traefik metrics refused", "metrics_addr", cfg.TraefikMetricsAddr, "error", err)
			os.Exit(1)
		}
		background.Go(func() { tap.Run(ctx, activityFlushTick) })
		background.Go(func() { counters.Run(ctx, activityReadInterval) })
		logger.Info("Ingress activity sensing armed", "metrics_addr", cfg.TraefikMetricsAddr,
			"read_interval", activityReadInterval, "write_interval", proxy.ActivityFlushInterval)
	} else {
		logger.Info("Ingress activity sensing off", "setting", "PREVIEWD_ACTIVITY_SENSING=0")
	}
	options := vcsForge.options
	if cfg.TriggerAPI {
		// The CI trigger API (V1.2 spec 3.4): its bearer token is a systemd
		// credential, held in memory as a digest only (api.WithTrigger).
		token, err := secrets.TriggerToken(cfg.TriggerTokenCredential)
		if err != nil {
			logger.Error("Trigger token refused", "credential", cfg.TriggerTokenCredential, "error", err)
			os.Exit(1)
		}
		options = append(slices.Clone(options), api.WithTrigger(token, vcsForge.heads, db))
		clear(token)
		if len(cfg.TriggerAllowedCIDRs) == 0 {
			logger.Warn("PREVIEWD_TRIGGER_ALLOWED_CIDRS is unset: the trigger API answers any source address")
		}
		logger.Info("Trigger API armed", "routes", "POST /api/v1/trigger, GET /api/v1/status/{envid}",
			"allowed_cidrs", len(cfg.TriggerAllowedCIDRs))
	}
	apiServer, err := api.NewServer(logger, cfg, webhookSecret, db, reconciler, vcsForge.github, options...)
	if err != nil {
		logger.Error("API server refused", "error", err)
		os.Exit(1)
	}
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.APIPort),
		Handler:           apiServer.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second, // an approval reads the forge before it answers
		IdleTimeout:       60 * time.Second,
	}

	// The webhook listener (C2, V1-I8): TLS, the certificate re-read on
	// SIGHUP, unless the plaintext opt-in is set.
	var certs *api.CertReloader
	if cfg.AllowPlaintextWebhooks {
		logger.Error("Opt-in active: webhooks are received in plaintext, delivery IDs and bodies readable on the network",
			"opt_in", "PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS")
	} else {
		certs, err = api.NewCertReloader(cfg.TLSCertFile, func() ([]byte, error) { return secrets.Credential(cfg.TLSKeyCredential) })
		if err != nil {
			logger.Error("Listener certificate refused", "cert_file", cfg.TLSCertFile, "error", err)
			os.Exit(1)
		}
		httpServer.TLSConfig = api.TLSConfig(certs)
	}
	if len(cfg.WebhookAllowedCIDRs) == 0 {
		logger.Warn("PREVIEWD_WEBHOOK_ALLOWED_CIDRS is unset: webhooks are accepted from any source address")
	}
	go reloadOnHangup(ctx, certs, logger)

	go func() {
		logger.Info("Ingress server running", "addr", httpServer.Addr, "tls", certs != nil)
		var err error
		if certs != nil {
			err = httpServer.ListenAndServeTLS("", "")
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	// Workers stop taking jobs; an interrupted job rolls back and records its
	// outcome before the database closes.
	background.Wait()

	logger.Info("Agent exited cleanly.")
}

// maxCABundleBytes bounds PREVIEWD_GHES_CA_FILE.
const maxCABundleBytes = 1 << 20

// newGHESClient builds the GitHub App client: the key from its systemd
// credential, held in memory only, the site CA when one is configured.
// newLogger is the daemon's logger: one JSON record per line. The JSON
// handler escapes every control character in keys and values, so a value
// from a webhook (a login, a label, an error quoting a payload) cannot end
// its record or forge another (CodeQL go/log-injection).
func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}

func newGHESClient(cfg *config.Config, logger *slog.Logger) (*vcs.Client, error) {
	key, err := secrets.Credential(cfg.GitHubAppKeyCredential)
	if err != nil {
		return nil, fmt.Errorf("GitHub App key: %w", err)
	}
	defer clear(key)
	var ca []byte
	if cfg.GHESCAFile != "" {
		if ca, err = readBounded(cfg.GHESCAFile, maxCABundleBytes); err != nil {
			return nil, fmt.Errorf("PREVIEWD_GHES_CA_FILE: %w", err)
		}
	}
	return vcs.NewClient(vcs.ClientConfig{BaseURL: cfg.GHESURL, AppID: cfg.GitHubAppID, KeyPEM: key, CAPEM: ca, Logger: logger})
}

func readBounded(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's CA bundle (PREVIEWD_GHES_CA_FILE, PREVIEWD_GITLAB_CA_FILE, PREVIEWD_FORGEJO_CA_FILE)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if data, err = io.ReadAll(io.LimitReader(f, limit+1)); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}

// reloadOnHangup re-reads the listener certificate on SIGHUP; a failed
// reload keeps the certificate in use. SIGHUP never terminates the daemon.
func reloadOnHangup(ctx context.Context, certs *api.CertReloader, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if certs == nil {
				logger.Info("SIGHUP: plaintext listener, no certificate to reload")
				continue
			}
			if err := certs.Reload(); err != nil {
				logger.Error("SIGHUP: listener certificate reload failed, the previous one stays in use", "error", err)
				continue
			}
			leaf := certs.Leaf()
			logger.Info("SIGHUP: listener certificate reloaded", "serial", leaf.SerialNumber.String(), "not_after", leaf.NotAfter)
		}
	}
}
