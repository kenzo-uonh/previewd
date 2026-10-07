package orchestrator

// The reconciler is the live implementation of the Worker and Supervisor
// processes of docs/formal/previewd.tla, on top of the durable queue
// (internal/store/jobs.go):
//
//	Startup        StartupSweep: host inventory -> queue sweep -> destroy
//	               what the database does not keep -> route post-condition
//	worker loop    AcquireJob, then
//	  deploy       ExecuteDeploy (remove previous version, fetch, network,
//	               build, stage secrets), StartContainer, PublishRoute,
//	               CommitDeploy; any failure rolls back and records FAILED
//	  teardown     ExecuteTeardown, CommitTeardown; a failure requeues with
//	               backoff, never FAILED

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/kenzo-uonh/previewd/internal/proxy"
	"github.com/kenzo-uonh/previewd/internal/store"
)

// Queue is the job queue the reconciler consumes (store.Store).
type Queue interface {
	Acquire(ctx context.Context, now time.Time) (store.Lease, bool, error)
	Finish(ctx context.Context, l store.Lease, status store.JobStatus) error
	Requeue(ctx context.Context, l store.Lease, notBefore time.Time) error
	StartupSweep(ctx context.Context, now time.Time, observed []store.Observation) (store.SweepResult, error)
}

// SecretSource returns the secrets to stage for a deploy.
type SecretSource interface {
	GetSecrets() map[string]string
}

// FetchFunc checks out commitSHA of cloneURL into destDir (vcs.FetchRepository).
type FetchFunc func(ctx context.Context, cloneURL, commitSHA, destDir string) error

// ReconcilerConfig wires the reconciler. Every dependency is required.
type ReconcilerConfig struct {
	Queue   Queue
	Engine  Engine
	Routes  RoutePublisher
	Stager  SecretStager
	Secrets SecretSource
	Fetch   FetchFunc
	Logger  *slog.Logger
	Domain  string
	AppPort int
	// Now and PollInterval default to time.Now and 2 s.
	Now          func() time.Time
	PollInterval time.Duration
}

// Reconciler runs the startup sweep and the deployment workers.
type Reconciler struct {
	cfg  ReconcilerConfig
	wake chan struct{}
}

// NewReconciler validates cfg.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Queue == nil || cfg.Engine == nil || cfg.Routes == nil || cfg.Stager == nil ||
		cfg.Secrets == nil || cfg.Fetch == nil || cfg.Logger == nil {
		return nil, errors.New("reconciler: every dependency is required")
	}
	if cfg.Domain == "" || cfg.AppPort <= 0 || cfg.AppPort > 65535 {
		return nil, fmt.Errorf("reconciler: invalid domain %q or application port %d", cfg.Domain, cfg.AppPort)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Reconciler{cfg: cfg, wake: make(chan struct{}, 1)}, nil
}

// Startup runs once, before the API and the workers serve. It fails closed:
// any error leaves the host in a state the database does not vouch for, so
// the daemon must not start.
func (r *Reconciler) Startup(ctx context.Context) error {
	log := r.cfg.Logger
	routes, removed, err := r.cfg.Routes.Inventory()
	if err != nil {
		return fmt.Errorf("startup sweep: %w", err)
	}
	for _, name := range removed {
		log.Warn("Removed a file Traefik could load from the routes directory", "file", name)
	}
	staged, err := r.cfg.Stager.List()
	if err != nil {
		return fmt.Errorf("startup sweep: %w", err)
	}
	states, err := r.cfg.Engine.Observe(ctx)
	if err != nil {
		return fmt.Errorf("startup sweep: observe engine: %w", err)
	}

	observed := observations(states, staged, routes)
	res, err := r.cfg.Queue.StartupSweep(ctx, r.cfg.Now(), observed)
	if err != nil {
		return fmt.Errorf("startup sweep: %w", err)
	}
	for _, env := range res.Destroy {
		if err := Teardown(ctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, env); err != nil {
			return fmt.Errorf("startup sweep: destroy %s: %w", env, err)
		}
		log.Info("Destroyed an environment the database does not keep", "environment_id", env)
	}

	// Post-condition: a route document exists only for an environment the
	// database keeps.
	kept := map[string]bool{}
	for _, o := range observed {
		kept[o.EnvID] = !slices.Contains(res.Destroy, o.EnvID)
	}
	left, _, err := r.cfg.Routes.Inventory()
	if err != nil {
		return fmt.Errorf("startup sweep: %w", err)
	}
	for _, env := range left {
		if !kept[env] {
			return fmt.Errorf("startup sweep: route document of %s survived the sweep", env)
		}
	}
	log.Info("Startup sweep complete", "epoch", res.Epoch, "observed", len(observed),
		"destroyed", len(res.Destroy), "routes_kept", len(left), "files_removed", len(removed))
	return nil
}

// observations merges the engine's, the stager's and the proxy's views into
// one Observation per environment, sorted by environment ID.
func observations(states map[string]EngineState, staged, routes []string) []store.Observation {
	byEnv := map[string]*store.Observation{}
	get := func(env string) *store.Observation {
		if o, ok := byEnv[env]; ok {
			return o
		}
		o := &store.Observation{EnvID: env}
		byEnv[env] = o
		return o
	}
	for env, st := range states {
		o := get(env)
		o.Running, o.NetworkBound, o.JobID = st.Running, st.NetworkBound, st.JobID
	}
	for _, env := range staged {
		get(env).SecretsMounted = true
	}
	for _, env := range routes {
		get(env).Routed = true
	}
	out := make([]store.Observation, 0, len(byEnv))
	for _, env := range slices.Sorted(maps.Keys(byEnv)) {
		out = append(out, *byEnv[env])
	}
	return out
}

// Notify wakes an idle worker: a job was queued.
func (r *Reconciler) Notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run starts workers and returns when ctx is done and every worker has
// finished its current job (rollback and status write included).
func (r *Reconciler) Run(ctx context.Context, workers int) {
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Go(func() { r.work(ctx) })
	}
	wg.Wait()
}

func (r *Reconciler) work(ctx context.Context) {
	for ctx.Err() == nil {
		l, ok, err := r.cfg.Queue.Acquire(ctx, r.cfg.Now())
		switch {
		case err != nil:
			if ctx.Err() == nil {
				r.cfg.Logger.Error("Acquire failed", "error", err)
			}
			r.idle(ctx)
		case !ok:
			r.idle(ctx)
		default:
			r.process(ctx, l)
		}
	}
}

func (r *Reconciler) idle(ctx context.Context) {
	t := time.NewTimer(r.cfg.PollInterval)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-r.wake:
	case <-t.C:
	}
}

func (r *Reconciler) process(ctx context.Context, l store.Lease) {
	log := r.cfg.Logger.With("job_id", l.JobID, "environment_id", l.EnvID, "type", string(l.Type),
		"repository", l.Source.Repo, "pr_number", l.Source.PRNumber, "commit_sha", l.Source.CommitSHA, "epoch", l.Epoch)
	switch l.Type {
	case store.JobDeploy:
		r.deploy(ctx, l, log)
	case store.JobTeardown:
		r.teardown(ctx, l, log)
	default:
		log.Error("Unknown job type: left IN_PROGRESS for the next startup sweep")
	}
}

// cleanupContext outlives a cancelled job so status writes and rollbacks
// complete.
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func (r *Reconciler) deploy(ctx context.Context, l store.Lease, log *slog.Logger) {
	log.Info("Deploying environment")
	err := r.runDeploy(ctx, l, log)
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	if err == nil {
		if err = r.cfg.Queue.Finish(cctx, l, store.StatusSuccess); err == nil {
			log.Info("Environment deployed")
			return
		}
		err = fmt.Errorf("commit deploy: %w", err)
	}
	// Roll back to absent: nothing of a deploy the database does not record
	// as SUCCESS may stay on the host, the route document least of all.
	log.Error("Deploy failed, rolling back", "error", err)
	if rbErr := Teardown(cctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, l.EnvID); rbErr != nil {
		log.Error("Rollback incomplete: the next startup sweep removes the rest", "error", rbErr)
	}
	if fErr := r.cfg.Queue.Finish(cctx, l, store.StatusFailed); fErr != nil {
		log.Error("Could not record the failed deploy", "error", fErr)
	}
}

func (r *Reconciler) runDeploy(ctx context.Context, l store.Lease, log *slog.Logger) (err error) {
	env := l.EnvID

	// ExecuteDeploy: remove the previous version, fetch, create the internal
	// network, build, stage the secrets on ramfs.
	if err := Teardown(ctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, env); err != nil {
		return fmt.Errorf("remove previous version: %w", err)
	}
	dir, err := os.MkdirTemp("", "previewd-build-")
	if err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			log.Error("Could not remove the build directory", "dir", dir, "error", rmErr)
		}
	}()
	if err := r.cfg.Fetch(ctx, l.Source.CloneURL, l.Source.CommitSHA, dir); err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	if err := r.cfg.Engine.ProvisionNetwork(ctx, env); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	tag := env + ":latest"
	if err := r.cfg.Engine.Build(ctx, dir, tag); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	secretsDir, err := r.cfg.Stager.Stage(env, r.cfg.Secrets.GetSecrets())
	if err != nil {
		return fmt.Errorf("stage secrets: %w", err)
	}

	// StartContainer.
	backend, err := r.cfg.Engine.Deploy(ctx, Environment{
		ID: env, Image: tag, Port: r.cfg.AppPort, Domain: r.cfg.Domain, JobID: l.JobID, SecretsDir: secretsDir,
	})
	if err != nil {
		return fmt.Errorf("start container: %w", err)
	}

	// PublishRoute.
	if err := r.cfg.Routes.Publish(proxy.Route{EnvID: env, Domain: r.cfg.Domain, Backend: backend}); err != nil {
		return fmt.Errorf("publish route: %w", err)
	}
	return nil
}

func (r *Reconciler) teardown(ctx context.Context, l store.Lease, log *slog.Logger) {
	log.Info("Tearing down environment")
	err := Teardown(ctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, l.EnvID)
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	if err != nil {
		notBefore := r.cfg.Now().Add(teardownBackoff(l.Attempts))
		log.Error("Teardown failed, requeued", "error", err, "attempt", l.Attempts+1, "not_before", notBefore)
		if rqErr := r.cfg.Queue.Requeue(cctx, l, notBefore); rqErr != nil {
			log.Error("Could not requeue the teardown: the next startup sweep requeues it", "error", rqErr)
		}
		return
	}
	if err := r.cfg.Queue.Finish(cctx, l, store.StatusSuccess); err != nil {
		log.Error("Could not record the teardown: the next startup sweep requeues it", "error", err)
		return
	}
	log.Info("Environment torn down")
}

// teardownBackoff doubles from 1 s and stops at 5 minutes.
func teardownBackoff(attempts int64) time.Duration {
	return min(time.Second<<min(max(attempts, 0), 9), 5*time.Minute)
}
