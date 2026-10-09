package orchestrator

// The reconciler is the live implementation of the Worker and Supervisor
// processes of docs/formal/previewd.tla, on top of the durable queue
// (internal/store/jobs.go):
//
//	Startup        StartupSweep: host inventory -> queue sweep -> destroy
//	               what the database does not keep -> route post-condition
//	worker loop    AcquireJob, then
//	  deploy       AuthorizeDeploy (V1, docs/formal/V1-model.md): classify
//	               the lease from GHES and record it (Classify), or park it
//	               (remove the previous version, PENDING_APPROVAL), or
//	               requeue it unclassified (GHES unavailable: remove a revoked
//	               version first, A2-6; park at the attempt ceiling); then
//	               ExecuteDeploy (remove previous version, fetch, network,
//	               build within the build bounds, stage the secret section of
//	               its trust), StartContainer, PublishRoute, CommitDeploy; any
//	               failure rolls back and records FAILED with the step that
//	               failed
//	  teardown     ExecuteTeardown, CommitTeardown; a failure requeues with
//	               backoff, never FAILED
//	Revalidator    every interval, each running environment is re-checked
//	               (D-V1-5); one no longer authorized, or unverifiable past
//	               the grace period, gets an internal teardown
//	Maintain       every prune interval, Prune with the builders of what
//	               exists on the host (V1 F3, V1-I6), then incremental_vacuum

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/kenzo-uonh/previewd/internal/proxy"
	"github.com/kenzo-uonh/previewd/internal/store"
)

// Queue is the job queue the reconciler consumes (store.Store).
type Queue interface {
	Acquire(ctx context.Context, now time.Time) (store.Lease, bool, error)
	Finish(ctx context.Context, l store.Lease, status store.JobStatus, now time.Time) error
	// Fail records a deploy FAILED with the step that failed.
	Fail(ctx context.Context, l store.Lease, failure store.Failure, now time.Time) error
	Requeue(ctx context.Context, l store.Lease, notBefore time.Time) error
	StartupSweep(ctx context.Context, now time.Time, observed []store.Observation) (store.SweepResult, error)
	// AuthorizeDeploy (V1).
	Classify(ctx context.Context, l store.Lease, c store.Classification) error
	Park(ctx context.Context, l store.Lease) error
	RunningVersion(ctx context.Context, envID string) (store.Job, bool, error)
	ApprovalLive(ctx context.Context, envID, commitSHA string) (bool, error)
	// Revalidator (D-V1-5).
	Running(ctx context.Context) ([]store.Job, error)
	EnqueueInternal(ctx context.Context, envID string, origin store.Origin, reason store.RevocationReason, now time.Time, audit store.AuditEvent) (int64, error)
	// Maintain (V1 F3).
	Prune(ctx context.Context, req store.PruneRequest) (store.PruneStats, error)
}

// Authorizer is the deploy gate (GHESAuthorizer).
type Authorizer interface {
	// Authorize classifies a leased deploy: ErrUnavailable requeues it,
	// ErrNotApproved parks it, anything else deploys nothing.
	Authorize(ctx context.Context, l store.Lease) (Decision, error)
	// Revalidate re-checks the running version a SUCCESS deploy built:
	// ErrNotApproved (a *RevokedError) tears it down, ErrUnavailable counts
	// toward the grace period.
	Revalidate(ctx context.Context, j store.Job) error
}

// SecretSource returns the secret section a deploy receives (V1-I2): the
// trusted section of repo, or its untrusted section, never the trusted one
// for an untrusted deploy unless fullOptIn (D-V1-1). secrets.Injector.
type SecretSource interface {
	Section(repo string, untrusted, fullOptIn bool) (map[string]string, error)
}

// FetchFunc checks out commitSHA of cloneURL into destDir (vcs.FetchRepository).
type FetchFunc func(ctx context.Context, cloneURL, commitSHA, destDir string) error

// ReconcilerConfig wires the reconciler. Every dependency is required.
type ReconcilerConfig struct {
	Queue      Queue
	Engine     Engine
	Routes     RoutePublisher
	Stager     SecretStager
	Secrets    SecretSource
	Authorizer Authorizer
	Fetch      FetchFunc
	Logger     *slog.Logger
	Domain     string
	AppPort    int
	// AllowedBaseImages (PREVIEWD_ALLOWED_BASE_IMAGES, canonical references)
	// and MaxBuildContextBytes (PREVIEWD_MAX_BUILD_CONTEXT_MIB) bound what the
	// preflight lets reach the engine (V1 F2). Both are required.
	AllowedBaseImages    map[string]bool
	MaxBuildContextBytes int64
	// MaxConcurrentBuilds and BuildTimeout are PREVIEWD_MAX_CONCURRENT_BUILDS
	// and PREVIEWD_BUILD_TIMEOUT (default 1 and 20 m): every build shares the
	// daemon-level BuildKit limits (D-V1-4), and a build past its timeout is
	// cancelled and fails its deploy.
	MaxConcurrentBuilds int
	BuildTimeout        time.Duration
	// Retention, DeliveryMaxAge, PruneInterval and PruneBatch drive Maintain
	// (PREVIEWD_RETENTION, PREVIEWD_DELIVERY_MAX_AGE, PREVIEWD_PRUNE_INTERVAL,
	// PREVIEWD_PRUNE_BATCH; default 720 h, 15 m, 1 h, 500).
	Retention      time.Duration
	DeliveryMaxAge time.Duration
	PruneInterval  time.Duration
	PruneBatch     int
	// RevalidateInterval and RevalidateGrace are
	// PREVIEWD_APPROVAL_REVALIDATE_INTERVAL and _GRACE (default 10 m, 1 h);
	// the grace is never shorter than the interval.
	RevalidateInterval time.Duration
	RevalidateGrace    time.Duration
	// AuthorizeMaxAttempts is the ceiling of AuthorizeDeploy attempts that
	// cannot classify a deploy (GHES unavailable, more than 1,000 reviews,
	// approvals changed during the read): the last one parks the deploy
	// instead of requeuing it (default 10).
	AuthorizeMaxAttempts int64
	// Now and PollInterval default to time.Now and 2 s.
	Now          func() time.Time
	PollInterval time.Duration
}

// Defaults of ReconcilerConfig.
const (
	defaultRevalidateInterval   = 10 * time.Minute
	defaultRevalidateGrace      = time.Hour
	defaultAuthorizeMaxAttempts = 10
	defaultBuildTimeout         = 20 * time.Minute
	maxConcurrentBuilds         = 16
	defaultRetention            = 720 * time.Hour
	defaultDeliveryMaxAge       = 15 * time.Minute
	defaultPruneInterval        = time.Hour
	defaultPruneBatch           = 500
	// minRetention keeps Prune far behind the host inventory it is given: a
	// job that becomes a builder after Observe returns finished during the
	// pass, long after now - retention, so that pass cannot prune it.
	minRetention = 24 * time.Hour
	// pruneYield is the pause between Prune's transactions: longer than the
	// longest sleep of SQLite's busy handler (100 ms), so a webhook's Enqueue
	// waiting for the lock retries in each gap instead of timing out behind
	// a long run of batches (a 500 GitHub does not redeliver).
	pruneYield = 150 * time.Millisecond
)

// ErrBuildTimeout fails a build still running at PREVIEWD_BUILD_TIMEOUT.
var ErrBuildTimeout = errors.New("build cancelled at PREVIEWD_BUILD_TIMEOUT")

// Reconciler runs the startup sweep, the deployment workers, the
// re-validation loop and the maintenance loop.
type Reconciler struct {
	cfg  ReconcilerConfig
	wake chan struct{}
	// builds holds one token per build in flight (MaxConcurrentBuilds).
	builds chan struct{}
}

// NewReconciler validates cfg.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Queue == nil || cfg.Engine == nil || cfg.Routes == nil || cfg.Stager == nil ||
		cfg.Secrets == nil || cfg.Authorizer == nil || cfg.Fetch == nil || cfg.Logger == nil {
		return nil, errors.New("reconciler: every dependency is required")
	}
	if cfg.RevalidateInterval <= 0 {
		cfg.RevalidateInterval = defaultRevalidateInterval
	}
	if cfg.RevalidateGrace <= 0 {
		cfg.RevalidateGrace = max(defaultRevalidateGrace, cfg.RevalidateInterval)
	}
	if cfg.RevalidateGrace < cfg.RevalidateInterval {
		return nil, fmt.Errorf("reconciler: re-validation grace %s is shorter than the interval %s", cfg.RevalidateGrace, cfg.RevalidateInterval)
	}
	if cfg.AuthorizeMaxAttempts <= 0 {
		cfg.AuthorizeMaxAttempts = defaultAuthorizeMaxAttempts
	}
	if len(cfg.AllowedBaseImages) == 0 || cfg.MaxBuildContextBytes <= 0 {
		return nil, fmt.Errorf("reconciler: the build preflight needs allowed base images and a positive context cap (got %d images, %d bytes)",
			len(cfg.AllowedBaseImages), cfg.MaxBuildContextBytes)
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
	if cfg.MaxConcurrentBuilds < 0 || cfg.MaxConcurrentBuilds > maxConcurrentBuilds || cfg.BuildTimeout < 0 {
		return nil, fmt.Errorf("reconciler: invalid build bounds (%d concurrent builds, timeout %s)", cfg.MaxConcurrentBuilds, cfg.BuildTimeout)
	}
	cfg.MaxConcurrentBuilds = cmp.Or(cfg.MaxConcurrentBuilds, 1)
	cfg.BuildTimeout = cmp.Or(cfg.BuildTimeout, defaultBuildTimeout)
	if cfg.Retention < 0 || cfg.DeliveryMaxAge < 0 || cfg.PruneInterval < 0 || cfg.PruneBatch < 0 {
		return nil, fmt.Errorf("reconciler: negative maintenance setting (retention %s, delivery max age %s, interval %s, batch %d)",
			cfg.Retention, cfg.DeliveryMaxAge, cfg.PruneInterval, cfg.PruneBatch)
	}
	cfg.Retention = cmp.Or(cfg.Retention, defaultRetention)
	cfg.DeliveryMaxAge = cmp.Or(cfg.DeliveryMaxAge, defaultDeliveryMaxAge)
	cfg.PruneInterval = cmp.Or(cfg.PruneInterval, defaultPruneInterval)
	cfg.PruneBatch = cmp.Or(cfg.PruneBatch, defaultPruneBatch)
	if cfg.Retention < minRetention {
		return nil, fmt.Errorf("reconciler: retention %s is shorter than %s", cfg.Retention, minRetention)
	}
	return &Reconciler{cfg: cfg, wake: make(chan struct{}, 1), builds: make(chan struct{}, cfg.MaxConcurrentBuilds)}, nil
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
	d, ok := r.authorizeDeploy(ctx, l, log)
	if !ok {
		return
	}
	log = log.With("trust", string(d.Trust))
	log.Info("Deploying environment")
	err := r.runDeploy(ctx, l, d, log)
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	if err == nil {
		if err = r.cfg.Queue.Finish(cctx, l, store.StatusSuccess, r.cfg.Now()); err == nil {
			log.Info("Environment deployed")
			return
		}
		err = failAt(store.FailureCommit, fmt.Errorf("commit deploy: %w", err))
	}
	// Roll back to absent: nothing of a deploy the database does not record
	// as SUCCESS may stay on the host, the route document least of all.
	failure := store.FailureNone
	var se *stepError
	if errors.As(err, &se) {
		failure = se.step
	}
	log.Error("Deploy failed, rolling back", "error", err, "failure", string(failure))
	if rbErr := Teardown(cctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, l.EnvID); rbErr != nil {
		log.Error("Rollback incomplete: the next startup sweep removes the rest", "error", rbErr)
	}
	var fErr error
	if failure == store.FailureNone {
		fErr = r.cfg.Queue.Finish(cctx, l, store.StatusFailed, r.cfg.Now())
	} else {
		fErr = r.cfg.Queue.Fail(cctx, l, failure, r.cfg.Now())
	}
	if fErr != nil {
		log.Error("Could not record the failed deploy", "error", fErr)
	}
}

// stepError tags a deploy failure with the step that failed, recorded as
// jobs.failure (closed vocabulary). A failure outside the vocabulary
// (removing the previous version, the build directory, the network) carries
// no tag and is recorded FAILED with no step.
type stepError struct {
	step store.Failure
	err  error
}

func (e *stepError) Error() string { return e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

func failAt(step store.Failure, err error) error { return &stepError{step: step, err: err} }

func (r *Reconciler) runDeploy(ctx context.Context, l store.Lease, d Decision, log *slog.Logger) (err error) {
	env := l.EnvID
	// The secret section of the deploy's trust (V1-I2), read before anything
	// changes on the host. Only an explicit trusted verdict gets the trusted
	// section.
	section, err := r.cfg.Secrets.Section(l.Source.Repo, d.Trust != store.TrustTrusted, d.FullSecrets)
	if err != nil {
		return failAt(store.FailureStage, fmt.Errorf("secrets: %w", err))
	}

	// ExecuteDeploy: remove the previous version, fetch, pack the context
	// and run the preflight (nothing reaches the engine before it passes),
	// create the internal network, build, stage the secrets on ramfs.
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
	srcDir := filepath.Join(dir, "src")
	if err := r.cfg.Fetch(ctx, l.Source.CloneURL, l.Source.CommitSHA, srcDir); err != nil {
		return failAt(store.FailureFetch, fmt.Errorf("fetch: %w", err))
	}
	buildContext, err := PrepareBuildContext(srcDir, filepath.Join(dir, "context.tar"), r.cfg.MaxBuildContextBytes, r.cfg.AllowedBaseImages)
	if err != nil {
		return failAt(store.FailurePreflight, fmt.Errorf("preflight: %w", err))
	}
	defer func() {
		if cErr := buildContext.Close(); cErr != nil {
			log.Error("Could not close the build context", "error", cErr)
		}
	}()
	if err := r.cfg.Engine.ProvisionNetwork(ctx, env); err != nil {
		return fmt.Errorf("network: %w", err)
	}
	tag := env + ":latest"
	if err := r.build(ctx, BuildSpec{ContextTar: buildContext, Tag: tag, EnvID: env, JobID: l.JobID}, log); err != nil {
		return failAt(store.FailureBuild, fmt.Errorf("build: %w", err))
	}
	secretsDir, err := r.cfg.Stager.Stage(env, section)
	if err != nil {
		return failAt(store.FailureStage, fmt.Errorf("stage secrets: %w", err))
	}

	// StartContainer.
	backend, err := r.cfg.Engine.Deploy(ctx, Environment{
		ID: env, Image: tag, Port: r.cfg.AppPort, Domain: r.cfg.Domain, JobID: l.JobID, SecretsDir: secretsDir,
	})
	if err != nil {
		return failAt(store.FailureStart, fmt.Errorf("start container: %w", err))
	}

	// PublishRoute.
	if err := r.cfg.Routes.Publish(proxy.Route{EnvID: env, Domain: r.cfg.Domain, Backend: backend}); err != nil {
		return failAt(store.FailureRoute, fmt.Errorf("publish route: %w", err))
	}
	return nil
}

// build runs one build within the build bounds (D-V1-4, V1-I12): it waits
// for one of MaxConcurrentBuilds slots, shared by every worker because
// every build shares the daemon-level BuildKit limits, and its request is
// cancelled at BuildTimeout (E0: closing the request stops the solve and
// its RUN processes). A build whose deadline passed fails even when the
// engine reports success: a cancelled build is never read as one.
func (r *Reconciler) build(ctx context.Context, spec BuildSpec, log *slog.Logger) error {
	select {
	case r.builds <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("wait for a build slot: %w", context.Cause(ctx))
	}
	defer func() { <-r.builds }()
	bctx, cancel := context.WithTimeoutCause(ctx, r.cfg.BuildTimeout, ErrBuildTimeout)
	defer cancel()
	err := r.cfg.Engine.Build(bctx, spec)
	cause := context.Cause(bctx)
	switch {
	case errors.Is(cause, ErrBuildTimeout):
		log.Error("Build cancelled at the build timeout", "build_timeout", r.cfg.BuildTimeout, "error", err)
		if err == nil {
			return fmt.Errorf("%w (%s): the engine reported success after the deadline", ErrBuildTimeout, r.cfg.BuildTimeout)
		}
		return fmt.Errorf("%w (%s): %w", ErrBuildTimeout, r.cfg.BuildTimeout, err)
	case cause != nil && err == nil:
		return fmt.Errorf("build cancelled: %w", cause)
	}
	return err
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
	if err := r.cfg.Queue.Finish(cctx, l, store.StatusSuccess, r.cfg.Now()); err != nil {
		log.Error("Could not record the teardown: the next startup sweep requeues it", "error", err)
		return
	}
	log.Info("Environment torn down")
}

// authorizeDeploy is AuthorizeDeploy: the lease is classified from GHES and
// the verdict recorded with the approval the authorizer confirmed, or the
// deploy is parked or requeued. ok is true only for a deploy classified in
// the database; nothing of an unclassified deploy reaches the host but the
// removal of the version it supersedes.
func (r *Reconciler) authorizeDeploy(ctx context.Context, l store.Lease, log *slog.Logger) (Decision, bool) {
	d, err := r.cfg.Authorizer.Authorize(ctx, l)
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	switch {
	case errors.Is(err, ErrNotApproved):
		r.park(cctx, l, log, err)
		return Decision{}, false
	case err != nil:
		r.retryAuthorization(cctx, l, log, err)
		return Decision{}, false
	}
	err = r.cfg.Queue.Classify(cctx, l, store.Classification(d))
	switch {
	case errors.Is(err, store.ErrLeaseLost):
		log.Error("Lease lost before the deploy was classified: nothing deployed", "error", err)
		return Decision{}, false
	case err != nil:
		// ErrApprovalChanged or ErrNotApproved: the approvals changed between
		// the GHES read and the record, so the grant to audit is not the one
		// confirmed. Any other failure recorded nothing either. Authorize
		// again, within the ceiling.
		r.retryAuthorization(cctx, l, log, fmt.Errorf("record the classification: %w", err))
		return Decision{}, false
	}
	attrs := []any{"trust", string(d.Trust)}
	if d.Approval != nil {
		attrs = append(attrs, "approver_login", d.Approval.ApproverLogin, "approver_id", d.Approval.ApproverID,
			"approved_via", string(d.Approval.Via), "review_id", d.Approval.ReviewID)
	}
	log.Info("Deploy authorized", attrs...)
	if d.FullSecrets {
		log.Error("Opt-in active: an approved untrusted deploy receives the trusted secret section",
			"opt_in", "PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS")
	}
	return d, true
}

// park refuses an unauthorized deploy: the version it supersedes is
// removed, then the job waits in PENDING_APPROVAL for an approval of its
// exact commit or a newer intent. When that removal fails the deploy is
// requeued instead, so no superseded version keeps running behind a parked
// job.
func (r *Reconciler) park(ctx context.Context, l store.Lease, log *slog.Logger, cause error) {
	if err := Teardown(ctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, l.EnvID); err != nil {
		notBefore := r.cfg.Now().Add(teardownBackoff(l.Attempts))
		log.Error("Could not remove the superseded version of a refused deploy: requeued", "error", err, "cause", cause, "not_before", notBefore)
		if rqErr := r.cfg.Queue.Requeue(ctx, l, notBefore); rqErr != nil {
			log.Error("Could not requeue the refused deploy: the next startup sweep fails it", "error", rqErr)
		}
		return
	}
	if err := r.cfg.Queue.Park(ctx, l); err != nil {
		log.Error("Could not park the refused deploy: the next startup sweep fails it", "error", err, "cause", cause)
		return
	}
	log.Warn("Deploy refused: parked until an approval of its exact commit", "reason", cause)
}

// retryAuthorization handles a deploy AuthorizeDeploy could not classify.
// Below the ceiling it is requeued unclassified with backoff, after the
// removal of a running version whose approval the database no longer
// holds live (A2-6, a DB read, no GHES call). At the ceiling it is parked
// instead of requeued forever: a persistent outage, or a pull request whose
// reviews cannot be read whole (more than 1,000), never deploys.
func (r *Reconciler) retryAuthorization(ctx context.Context, l store.Lease, log *slog.Logger, cause error) {
	if l.Attempts+1 >= r.cfg.AuthorizeMaxAttempts {
		log.Error("Deploy still unclassified at the attempt ceiling: parked", "attempts", l.Attempts+1, "error", cause)
		r.park(ctx, l, log, cause)
		return
	}
	if err := r.removeRevokedVersion(ctx, l.EnvID, log); err != nil {
		log.Error("Could not check or remove a revoked version: the next attempt retries", "error", err)
	}
	notBefore := r.cfg.Now().Add(authorizeBackoff(l.Attempts))
	log.Warn("Deploy not classified: requeued", "error", cause, "attempt", l.Attempts+1, "not_before", notBefore)
	if err := r.cfg.Queue.Requeue(ctx, l, notBefore); err != nil {
		log.Error("Could not requeue the unclassified deploy: the next startup sweep fails it", "error", err)
	}
}

// removeRevokedVersion destroys the version running in envID when it was
// built on an approval that is no longer live in the database (A2-6).
func (r *Reconciler) removeRevokedVersion(ctx context.Context, envID string, log *slog.Logger) error {
	v, ok, err := r.cfg.Queue.RunningVersion(ctx, envID)
	if err != nil || !ok || v.Trust != store.TrustUntrusted {
		return err
	}
	live, err := r.cfg.Queue.ApprovalLive(ctx, envID, v.Source.CommitSHA)
	if err != nil || live {
		return err
	}
	if err := Teardown(ctx, r.cfg.Engine, r.cfg.Routes, r.cfg.Stager, envID); err != nil {
		return fmt.Errorf("remove the revoked version built by job %d: %w", v.ID, err)
	}
	log.Warn("Removed a running version whose approval was revoked (A2-6)", "builder_job_id", v.ID, "revoked_commit", v.Source.CommitSHA)
	return nil
}

// authorizeBackoff doubles from 30 s and stops at 10 minutes: with the
// default ceiling, a deploy waits about an hour for GHES before it parks.
func authorizeBackoff(attempts int64) time.Duration {
	return min(30*time.Second<<min(max(attempts, 0), 5), 10*time.Minute)
}

// teardownBackoff doubles from 1 s and stops at 5 minutes.
func teardownBackoff(attempts int64) time.Duration {
	return min(time.Second<<min(max(attempts, 0), 9), 5*time.Minute)
}

// Revalidate runs the re-validation loop (D-V1-5, V1-I4) until ctx is done.
// Every interval, each running environment (store.Running) is re-checked
// against GHES. One that is no longer authorized gets an internal teardown
// at once; one that cannot be checked is kept until it has failed to be
// checked for the grace period, then torn down (fail closed). The failure
// count lives in memory: a restart begins a new grace period, and the
// startup sweep re-arms only through AuthorizeDeploy.
func (r *Reconciler) Revalidate(ctx context.Context) {
	failing := map[string]*streak{}
	t := time.NewTicker(r.cfg.RevalidateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.revalidateOnce(ctx, failing)
		}
	}
}

// streak is one environment's run of consecutive unverifiable checks.
type streak struct {
	since    time.Time // the first of them
	failures int64
}

// exhausted reports whether the streak has covered the grace period: by
// count, ceil(grace/interval) intervals after its first check, so jitter in
// the time a check returns never costs an extra interval; or by wall time,
// when passes run later than the interval.
func (s *streak) exhausted(now time.Time, interval, grace time.Duration) bool {
	intervals := int64((grace + interval - 1) / interval)
	return s.failures-1 >= intervals || now.Sub(s.since) >= grace
}

// revalidateOnce checks every running environment once. failing carries
// the unverifiable streaks across passes.
func (r *Reconciler) revalidateOnce(ctx context.Context, failing map[string]*streak) {
	jobs, err := r.cfg.Queue.Running(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.cfg.Logger.Error("Re-validation: could not list the running environments", "error", err)
		}
		return
	}
	running := make(map[string]bool, len(jobs))
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		running[j.EnvID] = true
		log := r.cfg.Logger.With("environment_id", j.EnvID, "builder_job_id", j.ID, "trust", string(j.Trust),
			"repository", j.Source.Repo, "pr_number", j.Source.PRNumber, "commit_sha", j.Source.CommitSHA)
		err := r.cfg.Authorizer.Revalidate(ctx, j)
		now := r.cfg.Now()
		switch {
		case err == nil:
			if st, ok := failing[j.EnvID]; ok {
				log.Info("Re-validation succeeded again", "unverifiable_since", st.since, "failed_checks", st.failures)
				delete(failing, j.EnvID)
			}
		case ctx.Err() != nil:
			return
		case errors.Is(err, ErrNotApproved):
			var reason store.RevocationReason
			var rev *RevokedError
			if errors.As(err, &rev) {
				reason = rev.Reason
			}
			log.Warn("Environment no longer authorized: tearing down", "reason", string(reason), "error", err)
			r.revalidationTeardown(ctx, j, reason, string(store.OriginRevalidation), log)
			delete(failing, j.EnvID)
		default:
			st, ok := failing[j.EnvID]
			if !ok {
				st = &streak{since: now}
				failing[j.EnvID] = st
			}
			st.failures++
			if !st.exhausted(now, r.cfg.RevalidateInterval, r.cfg.RevalidateGrace) {
				log.Warn("Environment could not be re-validated: kept within the grace period",
					"error", err, "unverifiable_since", st.since, "failed_checks", st.failures, "grace", r.cfg.RevalidateGrace)
				continue
			}
			log.Error("Environment unverifiable past the grace period: tearing down (fail closed)",
				"error", err, "unverifiable_since", st.since, "failed_checks", st.failures, "grace", r.cfg.RevalidateGrace)
			r.revalidationTeardown(ctx, j, "", string(store.RevokedRevalidationUnavailable), log)
			delete(failing, j.EnvID)
		}
	}
	for env := range failing {
		if !running[env] {
			delete(failing, env)
		}
	}
}

// revalidationTeardown queues the internal teardown of j's environment,
// pinned to j's commit: when a newer intent for another commit was
// recorded since the check, the store refuses it and that intent's own
// AuthorizeDeploy decides. With a reason, the live approval of the commit
// is revoked in the same transaction.
func (r *Reconciler) revalidationTeardown(ctx context.Context, j store.Job, reason store.RevocationReason, detail string, log *slog.Logger) {
	cctx, cancel := cleanupContext(ctx)
	defer cancel()
	src := j.Source
	id, err := r.cfg.Queue.EnqueueInternal(cctx, j.EnvID, store.OriginRevalidation, reason, r.cfg.Now(), store.AuditEvent{
		Kind: store.AuditTeardown, EnvID: j.EnvID, Repo: src.Repo, PRNumber: src.PRNumber, CommitSHA: src.CommitSHA, Detail: detail,
	})
	if err != nil {
		log.Error("Could not queue the re-validation teardown: the next pass retries", "error", err)
		return
	}
	log.Info("Re-validation teardown queued", "teardown_job_id", id)
	r.Notify()
}

// Maintain runs the database maintenance loop (V1 F3, V1-I6) until ctx is
// done: one Prune pass at once, then one every PruneInterval. Prune itself
// ends with incremental_vacuum. It runs only after Startup: the store
// refuses Prune before the sweep.
func (r *Reconciler) Maintain(ctx context.Context) {
	t := time.NewTicker(r.cfg.PruneInterval)
	defer t.Stop()
	for {
		r.pruneOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pruneOnce runs one Prune pass and logs what it deleted.
func (r *Reconciler) pruneOnce(ctx context.Context) {
	stats, err := r.prune(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.cfg.Logger.Error("Prune pass failed: the next interval retries", "error", err)
		}
		return
	}
	r.cfg.Logger.Info("Prune pass complete", "jobs", stats.Jobs, "deliveries", stats.Deliveries,
		"approvals", stats.Approvals, "boots", stats.Boots, "max_batch", stats.MaxBatch, "batch", r.cfg.PruneBatch)
}

// prune reads the builders of every environment on the host, then prunes.
// It fails closed: without the host's view (Observe fails), nothing is
// pruned, since Prune would then delete the builders the sweep reads
// (V1-model.md A1-6).
func (r *Reconciler) prune(ctx context.Context) (store.PruneStats, error) {
	states, err := r.cfg.Engine.Observe(ctx)
	if err != nil {
		return store.PruneStats{}, fmt.Errorf("prune: observe engine: %w", err)
	}
	var builders []int64
	for _, st := range states {
		if st.JobID > 0 {
			builders = append(builders, st.JobID)
		}
	}
	slices.Sort(builders)
	stats, err := r.cfg.Queue.Prune(ctx, store.PruneRequest{
		Now: r.cfg.Now(), Retention: r.cfg.Retention, DeliveryMaxAge: r.cfg.DeliveryMaxAge,
		Batch: r.cfg.PruneBatch, Builders: builders, Yield: pruneYield,
	})
	if err != nil {
		return stats, fmt.Errorf("prune: %w", err)
	}
	return stats, nil
}
