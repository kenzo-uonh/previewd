package orchestrator

import (
	"archive/tar"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/proxy"
	"github.com/kenzo-uonh/previewd/internal/store"
)

const testEnv = "pr-7-0a0a0a0a0a"

// testBase is the allowlisted base image of the tests, in canonical form.
const testBase = "docker.io/library/busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"

var testBases = map[string]bool{testBase: true}

const testDockerfile = "FROM busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e\nRUN true\n"

// writeCheckout is a checkout holding only a Dockerfile.
func writeCheckout(dest, dockerfile string) error {
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dest, dockerfileName), []byte(dockerfile), 0o600)
}

// hostEngine is a fake Docker host.
type hostEngine struct {
	mu    sync.Mutex
	envs  map[string]EngineState
	fail  map[string]error // step -> error
	calls []string
	// built is the Dockerfile of each build context received, in order.
	built []string
	// buildHook, when set, runs inside Build after the build step is
	// recorded, without the lock: a slow or hanging build.
	buildHook func(ctx context.Context) error
	// images is the size of each environment's image: a successful build
	// adds it, Destroy and PruneImages remove it. keeps is the keep list of
	// each PruneImages call.
	images map[string]int64
	keeps  [][]string
	// cache counts build cache records since the last PruneBuildCache:
	// every build adds one, whatever its outcome.
	cache int
	// free is what FreeDisk reports.
	free int64
}

func newHostEngine() *hostEngine {
	return &hostEngine{envs: map[string]EngineState{}, fail: map[string]error{}, images: map[string]int64{}, free: 1 << 40}
}

func (h *hostEngine) step(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, name)
	return h.fail[name]
}

func (h *hostEngine) set(env string, f func(*EngineState)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.envs[env]
	f(&st)
	h.envs[env] = st
}

func (h *hostEngine) Ping(context.Context) error { return nil }
func (h *hostEngine) Logs(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("no logs")
}
func (h *hostEngine) Close() error { return nil }

// Build records the Dockerfile of the context it is streamed: the tar the
// preflight validated, never a host path.
func (h *hostEngine) Build(ctx context.Context, spec BuildSpec) error {
	if err := h.step("build"); err != nil {
		return err
	}
	h.mu.Lock()
	h.cache++
	h.mu.Unlock()
	if h.buildHook != nil {
		if err := h.buildHook(ctx); err != nil {
			return err
		}
	}
	if _, err := buildOptions(spec); err != nil {
		return err
	}
	dockerfile, err := tarFile(spec.ContextTar, dockerfileName)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.built = append(h.built, dockerfile)
	h.images[spec.EnvID] = 100 << 20
	return nil
}

func (h *hostEngine) PruneImages(_ context.Context, keep []string) (int64, error) {
	if err := h.step("prune-images"); err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keeps = append(h.keeps, slices.Clone(keep))
	var reclaimed int64
	for env, size := range h.images {
		if !slices.Contains(keep, env) {
			reclaimed += size
			delete(h.images, env)
		}
	}
	return reclaimed, nil
}

func (h *hostEngine) PruneBuildCache(context.Context) (int64, error) {
	if err := h.step("prune-cache"); err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.cache
	h.cache = 0
	return int64(n) << 20, nil
}

func (h *hostEngine) FreeDisk(context.Context) (int64, error) {
	if err := h.step("free-disk"); err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.free, nil
}

// tarFile reads the content of name from a tar stream.
func tarFile(r io.Reader, name string) (string, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return "", fmt.Errorf("%s not in the build context: %w", name, err)
		}
		if hdr.Name == name {
			b, err := io.ReadAll(tr)
			return string(b), err
		}
	}
}

func (h *hostEngine) BuildProbe(context.Context, netip.AddrPort) error { return h.step("probe") }

func (h *hostEngine) ProvisionNetwork(_ context.Context, env string) error {
	if err := h.step("network"); err != nil {
		return err
	}
	h.set(env, func(st *EngineState) { st.NetworkBound = true })
	return nil
}

func (h *hostEngine) Deploy(_ context.Context, e Environment) (netip.AddrPort, error) {
	if err := h.step("deploy"); err != nil {
		return netip.AddrPort{}, err
	}
	h.set(e.ID, func(st *EngineState) { st.Running, st.Containers, st.JobID = true, 1, e.JobID })
	return netip.MustParseAddrPort("172.31.0.2:8080"), nil
}

func (h *hostEngine) Destroy(_ context.Context, env string) error {
	if err := h.step("destroy"); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.envs, env)
	delete(h.images, env)
	return nil
}

func (h *hostEngine) Observe(context.Context) (map[string]EngineState, error) {
	if err := h.step("observe"); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.envs), nil
}

// memStager is a fake secret stager; content keeps what each environment
// was last given.
type memStager struct {
	mu      sync.Mutex
	staged  map[string]bool
	content map[string]map[string]string
	failErr error
	listErr error
}

func (m *memStager) Stage(env string, secrets map[string]string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return "", m.failErr
	}
	m.staged[env] = true
	if m.content == nil {
		m.content = map[string]map[string]string{}
	}
	m.content[env] = maps.Clone(secrets)
	return "/run/previewd/secrets/" + env, nil
}

func (m *memStager) Remove(env string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.staged, env)
	return nil
}

func (m *memStager) List() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.staged)), m.listErr
}

// sectionSecrets is the sectioned secrets file of acme/app (V1-I2).
type sectionSecrets struct{}

func (sectionSecrets) Section(repo string, untrusted, fullOptIn bool) (map[string]string, error) {
	if repo != "acme/app" {
		return map[string]string{}, nil
	}
	if untrusted && !fullOptIn {
		return map[string]string{"TOKEN": "sandbox-value"}, nil
	}
	return map[string]string{"TOKEN": "trusted-value"}, nil
}

// fakeAuthorizer is the gate the reconciler tests drive: authorize and
// revalidate answer for each call; by default every deploy is trusted and
// every running environment still authorized.
type fakeAuthorizer struct {
	mu         sync.Mutex
	authorize  func(store.Lease) (Decision, error)
	revalidate func(store.Job) error
	authorized int
}

func (f *fakeAuthorizer) Authorize(_ context.Context, l store.Lease) (Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorized++
	if f.authorize == nil {
		return Decision{Trust: store.TrustTrusted}, nil
	}
	return f.authorize(l)
}

func (f *fakeAuthorizer) Revalidate(_ context.Context, j store.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revalidate == nil {
		return nil
	}
	return f.revalidate(j)
}

func (f *fakeAuthorizer) set(authorize func(store.Lease) (Decision, error), revalidate func(store.Job) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorize, f.revalidate = authorize, revalidate
}

type rig struct {
	t        *testing.T
	dbPath   string
	queue    *store.Store
	engine   *hostEngine
	stager   *memStager
	routes   RoutePublisher
	routeDir string
	fetchErr error
	// dockerfile is what the fake fetch checks out (testDockerfile when "").
	dockerfile string
	now        time.Time
	seq        int64
	auth       *fakeAuthorizer
	// interval and grace of the Revalidator; 0 for the defaults.
	interval, grace time.Duration
	maxAttempts     int64
	// Build bounds and maintenance; 0 for the defaults.
	maxBuilds     int
	buildTimeout  time.Duration
	pruneInterval time.Duration
	// Auto-cleanup (V1 F5); 0 for the defaults. buildDir is the rig's own.
	minFreeDisk int64
	envTTL      time.Duration
	disableTTL  bool
	buildDir    string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	routeDir := filepath.Join(dir, "routes")
	if err := os.Mkdir(routeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pub, err := proxy.NewPublisher(routeDir)
	if err != nil {
		t.Fatal(err)
	}
	buildDir := filepath.Join(dir, "tmp")
	if err := os.Mkdir(buildDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := &rig{
		t: t, dbPath: filepath.Join(dir, "previewd.sqlite"), buildDir: buildDir,
		engine: newHostEngine(), stager: &memStager{staged: map[string]bool{}},
		routes: pub, routeDir: routeDir, now: time.UnixMilli(1_800_000_000_000), auth: &fakeAuthorizer{},
	}
	r.open()
	return r
}

func (r *rig) open() {
	r.t.Helper()
	q, err := store.NewStore(context.Background(), r.dbPath)
	if err != nil {
		r.t.Fatal(err)
	}
	r.queue = q
	r.t.Cleanup(func() {
		if err := q.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			r.t.Error(err)
		}
	})
}

// crash drops the daemon: the next reconciler opens the database afresh.
func (r *rig) crash() {
	r.t.Helper()
	if err := r.queue.Close(); err != nil {
		r.t.Fatal(err)
	}
	r.open()
}

func (r *rig) reconciler() *Reconciler {
	r.t.Helper()
	rec, err := NewReconciler(ReconcilerConfig{
		Queue: r.queue, Engine: r.engine, Routes: r.routes, Stager: r.stager,
		Secrets: sectionSecrets{}, Authorizer: r.auth,
		RevalidateInterval: r.interval, RevalidateGrace: r.grace, AuthorizeMaxAttempts: r.maxAttempts,
		MaxConcurrentBuilds: r.maxBuilds, BuildTimeout: r.buildTimeout, PruneInterval: r.pruneInterval, PruneBatch: 2,
		MinFreeDiskBytes: r.minFreeDisk, EnvTTL: r.envTTL, DisableTTL: r.disableTTL, BuildDir: r.buildDir,
		Fetch: func(_ context.Context, _, _, dest string) error {
			if r.fetchErr != nil {
				return r.fetchErr
			}
			return writeCheckout(dest, cmp.Or(r.dockerfile, testDockerfile))
		},
		AllowedBaseImages: testBases, MaxBuildContextBytes: 1 << 20,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Domain: "local.previewd", AppPort: 8080,
		Now: func() time.Time { return r.now }, PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return rec
}

func (r *rig) enqueue(typ store.JobType) {
	r.t.Helper()
	r.enqueueCommit(typ, "0123456789abcdef0123456789abcdef01234567")
}

// enqueueCommit queues a webhook job for commit: a deploy of another commit
// is a push, which revokes the approvals of every other commit.
func (r *rig) enqueueCommit(typ store.JobType, commit string) {
	r.t.Helper()
	r.seq++
	id := string(rune('a'+r.seq)) + "-delivery"
	sum := sha256.Sum256([]byte(id))
	v, _, err := r.queue.Enqueue(context.Background(), store.Delivery{
		ID: id, PayloadSHA256: hex.EncodeToString(sum[:]), EnvID: testEnv, Type: typ, Seq: r.seq,
		Source: store.Source{Repo: "acme/app", HeadRepo: "acme/app", PRNumber: 7, OpenerLogin: "opener", OpenerID: 4242,
			CommitSHA: commit, CloneURL: "https://git.example.internal/acme/app.git"},
		ReceivedAt: r.now,
	})
	if err != nil || v != store.VerdictAccepted {
		r.t.Fatalf("enqueue: %s, %v", v, err)
	}
}

// drain runs one worker until no job is QUEUED or IN_PROGRESS.
func (r *rig) drain(rec *Reconciler) []store.Job {
	r.t.Helper()
	return r.drainWith(rec, 1)
}

// drainWith runs workers until no job is QUEUED or IN_PROGRESS.
func (r *rig) drainWith(rec *Reconciler, workers int) []store.Job {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Run(ctx, workers)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err := r.queue.Jobs(context.Background())
		if err != nil {
			r.t.Fatal(err)
		}
		busy := false
		for _, j := range jobs {
			busy = busy || j.Status == store.StatusQueued || j.Status == store.StatusInProgress
		}
		if !busy {
			return jobs
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatal("queue did not drain")
	return nil
}

func (r *rig) routeFiles() []string {
	r.t.Helper()
	entries, err := os.ReadDir(r.routeDir)
	if err != nil {
		r.t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func lastStatus(jobs []store.Job) store.JobStatus { return jobs[len(jobs)-1].Status }

func TestReconcilerDeploysAndTearsDown(t *testing.T) {
	r := newRig(t)
	rec := r.reconciler()
	if err := rec.Startup(context.Background()); err != nil {
		t.Fatal(err)
	}

	r.enqueue(store.JobDeploy)
	jobs := r.drain(rec)
	if lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("deploy job = %+v", jobs)
	}
	st := r.engine.envs[testEnv]
	if !st.Running || !st.NetworkBound || st.JobID != jobs[0].ID || !r.stager.staged[testEnv] {
		t.Fatalf("host after deploy: %+v staged=%v", st, r.stager.staged)
	}
	if got := r.routeFiles(); !slices.Equal(got, []string{testEnv + ".yml"}) {
		t.Fatalf("route files = %v", got)
	}
	// ExecuteDeploy removes the previous version before building; the
	// first build after the start prunes the build cache first, every build
	// checks the free-disk floor and prunes the build cache after it.
	if want := []string{"observe", "destroy", "network", "prune-cache", "free-disk", "build", "prune-cache", "deploy"}; !slices.Equal(r.engine.calls, want) {
		t.Fatalf("engine calls = %v, want %v", r.engine.calls, want)
	}

	r.enqueue(store.JobTeardown)
	jobs = r.drain(rec)
	if lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("teardown job = %+v", jobs)
	}
	if len(r.engine.envs) != 0 || len(r.stager.staged) != 0 || len(r.routeFiles()) != 0 {
		t.Fatalf("host after teardown: engine %v staged %v routes %v", r.engine.envs, r.stager.staged, r.routeFiles())
	}
}

// Any failing deploy step rolls back to absent and records FAILED with the
// step that failed: no route, container, network or staging survives.
func TestReconcilerDeployFailureRollsBack(t *testing.T) {
	failures := map[string]store.Failure{
		"fetch": store.FailureFetch, "preflight": store.FailurePreflight, "network": store.FailureNone,
		"build": store.FailureBuild, "stage": store.FailureStage, "deploy": store.FailureStart, "publish": store.FailureRoute,
	}
	for _, step := range slices.Sorted(maps.Keys(failures)) {
		t.Run(step, func(t *testing.T) {
			r := newRig(t)
			boom := errors.New(step + " failed")
			switch step {
			case "fetch":
				r.fetchErr = boom
			case "preflight":
				r.dockerfile = "FROM busybox:latest\n"
			case "stage":
				r.stager.failErr = boom
			case "publish":
				r.routes = failingPublish{RoutePublisher: r.routes, err: boom}
			default:
				r.engine.fail[step] = boom
			}
			rec := r.reconciler()
			if err := rec.Startup(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.enqueue(store.JobDeploy)
			jobs := r.drain(rec)
			if lastStatus(jobs) != store.StatusFailed || jobs[len(jobs)-1].Failure != failures[step] {
				t.Fatalf("job = %+v, want FAILED with failure %q", jobs, failures[step])
			}
			if len(r.engine.envs) != 0 || len(r.stager.staged) != 0 || len(r.routeFiles()) != 0 {
				t.Fatalf("leftovers: engine %v staged %v routes %v", r.engine.envs, r.stager.staged, r.routeFiles())
			}
		})
	}
}

type failingPublish struct {
	RoutePublisher
	err error
}

func (f failingPublish) Publish(proxy.Route) error { return f.err }

// A failed teardown is requeued with backoff, never FAILED, then succeeds.
func TestReconcilerTeardownRequeues(t *testing.T) {
	r := newRig(t)
	rec := r.reconciler()
	if err := rec.Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.engine.fail["destroy"] = errors.New("daemon busy")
	r.enqueue(store.JobTeardown)

	l, ok, err := r.queue.Acquire(context.Background(), r.now)
	if err != nil || !ok {
		t.Fatalf("Acquire = %v, %v", ok, err)
	}
	rec.process(context.Background(), l)
	jobs, err := r.queue.Jobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if j := jobs[0]; j.Status != store.StatusQueued || j.Attempts != 1 || j.NotBefore != r.now.Add(time.Second).UnixMilli() {
		t.Fatalf("after a failed teardown: %+v", j)
	}

	delete(r.engine.fail, "destroy")
	r.now = r.now.Add(time.Second)
	if jobs := r.drain(rec); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("teardown after backoff = %+v", jobs)
	}
}

// Startup collects every route document the database does not keep: crash
// debris, foreign files, routes of leftovers no job tracks.
func TestStartupCollectsOrphanedRoutes(t *testing.T) {
	r := newRig(t)
	for name, content := range map[string]string{
		testEnv + ".yml":              `{"http":{}}`, // no job, no container
		"pr-9-0909090909.yml":         `{"http":{}}`, // stray container below
		".pr-8-0808080808.yml.tmp-42": "partial",
		"injected.yaml":               "http: {}",
	} {
		if err := os.WriteFile(filepath.Join(r.routeDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r.engine.envs["pr-9-0909090909"] = EngineState{Running: true, NetworkBound: true, Containers: 1}
	r.stager.staged["pr-9-0909090909"] = true

	if err := r.reconciler().Startup(context.Background()); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if got := r.routeFiles(); len(got) != 0 {
		t.Fatalf("route files left: %v", got)
	}
	if len(r.engine.envs) != 0 || len(r.stager.staged) != 0 {
		t.Fatalf("leftovers: engine %v staged %v", r.engine.envs, r.stager.staged)
	}
}

// After a daemon crash the database keeps an intact environment, route
// included. Once its route document is lost, the environment no longer
// matches: it is destroyed and its deploy re-armed, then rebuilt.
func TestStartupKeepsThenRebuildsDeployedEnvironment(t *testing.T) {
	r := newRig(t)
	rec := r.reconciler()
	if err := rec.Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.enqueue(store.JobDeploy)
	r.drain(rec)

	r.crash()
	if err := r.reconciler().Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.routeFiles(); !slices.Equal(got, []string{testEnv + ".yml"}) || !r.engine.envs[testEnv].Running {
		t.Fatalf("kept environment lost: routes %v engine %v", got, r.engine.envs)
	}

	if err := os.Remove(filepath.Join(r.routeDir, testEnv+".yml")); err != nil {
		t.Fatal(err)
	}
	r.crash()
	rec = r.reconciler()
	if err := rec.Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.engine.envs[testEnv]; ok {
		t.Fatal("environment without its route document kept")
	}
	jobs := r.drain(rec)
	if lastStatus(jobs) != store.StatusSuccess || !r.engine.envs[testEnv].Running || len(r.routeFiles()) != 1 {
		t.Fatalf("re-armed deploy: jobs %+v engine %v routes %v", jobs, r.engine.envs, r.routeFiles())
	}
}

type stubbornRoutes struct{ RoutePublisher }

func (stubbornRoutes) Remove(string) error { return nil } // claims success, removes nothing

// Fail closed: startup refuses to serve when the host cannot be inventoried
// or a route document survives the sweep.
func TestStartupFailsClosed(t *testing.T) {
	cases := map[string]func(r *rig){
		"engine inventory": func(r *rig) { r.engine.fail["observe"] = errors.New("daemon down") },
		"staging listing":  func(r *rig) { r.stager.listErr = errors.New("unexpected entry") },
		"routes dir entry": func(r *rig) {
			if err := os.Mkdir(filepath.Join(r.routeDir, "nested"), 0o755); err != nil {
				r.t.Fatal(err)
			}
		},
		"destroy fails": func(r *rig) {
			r.engine.envs["pr-9-0909090909"] = EngineState{Running: true}
			r.engine.fail["destroy"] = errors.New("daemon busy")
		},
		"route survives": func(r *rig) {
			if err := os.WriteFile(filepath.Join(r.routeDir, "pr-9-0909090909.yml"), []byte("{}"), 0o644); err != nil {
				r.t.Fatal(err)
			}
			r.routes = stubbornRoutes{r.routes}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			setup(r)
			if err := r.reconciler().Startup(context.Background()); err == nil {
				t.Fatal("Startup succeeded")
			}
		})
	}
}

func TestNewReconcilerRequiresDependencies(t *testing.T) {
	if _, err := NewReconciler(ReconcilerConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

// The build preflight cannot be configured away: no allowlist or no
// context cap refuses the reconciler.
func TestNewReconcilerRequiresThePreflight(t *testing.T) {
	r := newRig(t)
	for name, mutate := range map[string]func(*ReconcilerConfig){
		"no base image":   func(c *ReconcilerConfig) { c.AllowedBaseImages = nil },
		"empty allowlist": func(c *ReconcilerConfig) { c.AllowedBaseImages = map[string]bool{} },
		"no context cap":  func(c *ReconcilerConfig) { c.MaxBuildContextBytes = 0 },
		"negative cap":    func(c *ReconcilerConfig) { c.MaxBuildContextBytes = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := ReconcilerConfig{
				Queue: r.queue, Engine: r.engine, Routes: r.routes, Stager: r.stager, Secrets: sectionSecrets{},
				Authorizer: r.auth, Fetch: func(context.Context, string, string, string) error { return nil },
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Domain: "local.previewd", AppPort: 8080,
				AllowedBaseImages: testBases, MaxBuildContextBytes: 1 << 20,
			}
			mutate(&cfg)
			if _, err := NewReconciler(cfg); err == nil {
				t.Fatal("reconciler without the build preflight accepted")
			}
		})
	}
}

// V1-I5: a Dockerfile the preflight refuses fails the deploy before any
// request reaches the engine: no network, no build. An accepted one is
// streamed as the tar the preflight validated.
func TestPreflightRunsBeforeTheEngine(t *testing.T) {
	for name, df := range map[string]string{
		"RUN --network=host": "FROM " + pinned + "\nRUN --network=host curl http://10.0.0.1\n",
		"ADD URL":            "FROM " + pinned + "\nADD https://example.invalid/x /x\n",
		"unpinned FROM":      "FROM busybox:latest\n",
		"syntax directive":   "# syntax=docker/dockerfile:1\nFROM " + pinned + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.dockerfile = df
			rec := r.reconciler()
			if err := rec.Startup(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.enqueue(store.JobDeploy)
			if jobs := r.drain(rec); lastStatus(jobs) != store.StatusFailed {
				t.Fatalf("jobs = %+v, want FAILED", jobs)
			}
			r.engine.mu.Lock()
			defer r.engine.mu.Unlock()
			if slices.Contains(r.engine.calls, "network") || slices.Contains(r.engine.calls, "build") || len(r.engine.built) != 0 {
				t.Fatalf("engine calls %q: a refused Dockerfile reached the engine", r.engine.calls)
			}
		})
	}
	t.Run("accepted", func(t *testing.T) {
		r := newRig(t)
		rec := r.reconciler()
		if err := rec.Startup(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.enqueue(store.JobDeploy)
		if jobs := r.drain(rec); lastStatus(jobs) != store.StatusSuccess {
			t.Fatalf("jobs = %+v, want SUCCESS", jobs)
		}
		r.engine.mu.Lock()
		defer r.engine.mu.Unlock()
		if len(r.engine.built) != 1 || r.engine.built[0] != testDockerfile {
			t.Fatalf("built %q, want the validated Dockerfile", r.engine.built)
		}
	})
}

func TestObservationsMergeSources(t *testing.T) {
	got := observations(
		map[string]EngineState{"pr-2-0b0b0b0b0b": {Running: true, NetworkBound: true, JobID: 4}},
		[]string{"pr-2-0b0b0b0b0b", "pr-1-0a0a0a0a0a"},
		[]string{"pr-3-0c0c0c0c0c", "pr-2-0b0b0b0b0b"},
	)
	want := []store.Observation{
		{EnvID: "pr-1-0a0a0a0a0a", SecretsMounted: true},
		{EnvID: "pr-2-0b0b0b0b0b", Running: true, NetworkBound: true, SecretsMounted: true, Routed: true, JobID: 4},
		{EnvID: "pr-3-0c0c0c0c0c", Routed: true},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("observations = %+v, want %+v", got, want)
	}
}

// untrusted is the authorizer's answer for an untrusted PR: the newest live
// approval of the lease's commit, as GHES would confirm it, or a refusal.
func (r *rig) untrusted(fullSecrets bool) func(store.Lease) (Decision, error) {
	return func(l store.Lease) (Decision, error) {
		a, live, err := r.queue.LiveApproval(context.Background(), l.EnvID, l.Source.CommitSHA)
		if err != nil {
			return Decision{}, err
		}
		if !live {
			return Decision{}, refuse("", "no live approval")
		}
		return Decision{Trust: store.TrustUntrusted, Approval: &a, FullSecrets: fullSecrets}, nil
	}
}

// step acquires the next job at r.now and runs it on this goroutine.
func (r *rig) step(rec *Reconciler) store.Lease {
	r.t.Helper()
	l, ok, err := r.queue.Acquire(context.Background(), r.now)
	if err != nil || !ok {
		r.t.Fatalf("Acquire = %v, %v", ok, err)
	}
	rec.process(context.Background(), l)
	return l
}

func (r *rig) jobs() []store.Job {
	r.t.Helper()
	jobs, err := r.queue.Jobs(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return jobs
}

func (r *rig) started() *Reconciler {
	r.t.Helper()
	rec := r.reconciler()
	if err := rec.Startup(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	return rec
}

// built reports whether the engine was asked to build since the last reset.
func (r *rig) built() bool {
	r.engine.mu.Lock()
	defer r.engine.mu.Unlock()
	return slices.Contains(r.engine.calls, "build") || slices.Contains(r.engine.calls, "deploy")
}

func (r *rig) running() bool {
	r.engine.mu.Lock()
	defer r.engine.mu.Unlock()
	return r.engine.envs[testEnv].Running
}

// V1-I2: each deploy stages the secret section of its own trust; an
// untrusted deploy never receives the trusted value unless its repository
// is opted in (D-V1-1).
func TestAuthorizeDeployStagesTheSectionOfItsTrust(t *testing.T) {
	for name, tc := range map[string]struct {
		untrusted, full bool
		want            string
	}{
		"trusted":                  {false, false, "trusted-value"},
		"untrusted":                {true, false, "sandbox-value"},
		"untrusted, D-V1-1 opt-in": {true, true, "trusted-value"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			rec := r.started()
			want := store.TrustTrusted
			if tc.untrusted {
				r.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
				r.auth.set(r.untrusted(tc.full), nil)
				want = store.TrustUntrusted
			}
			r.enqueue(store.JobDeploy)
			jobs := r.drain(rec)
			if j := jobs[len(jobs)-1]; j.Status != store.StatusSuccess || j.Trust != want {
				t.Fatalf("deploy = %+v, want SUCCESS %s", j, want)
			}
			if got := r.stager.content[testEnv]["TOKEN"]; got != tc.want {
				t.Fatalf("staged TOKEN = %q, want %q", got, tc.want)
			}
		})
	}
}

// V1-I1: a refused deploy is parked before anything is fetched or built,
// and the version it supersedes is removed with its route and secrets.
func TestAuthorizeDeployParksAndRemovesThePreviousVersion(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	if !r.running() {
		t.Fatal("the trusted version is not running")
	}
	r.engine.calls = nil
	r.auth.set(func(store.Lease) (Decision, error) {
		return Decision{}, refuse("", "fork without approval")
	}, nil)
	r.enqueue(store.JobDeploy)
	r.step(rec)
	jobs := r.jobs()
	if j := jobs[len(jobs)-1]; j.Status != store.StatusPendingApproval || j.Trust != store.TrustUnclassified {
		t.Fatalf("refused deploy = %+v, want PENDING_APPROVAL, unclassified", j)
	}
	if r.built() || r.running() || r.stager.staged[testEnv] || len(r.routeFiles()) != 0 {
		t.Fatalf("after the park: calls %v, staged %v, routes %v", r.engine.calls, r.stager.staged, r.routeFiles())
	}
}

// GHES unavailable: requeued unclassified with backoff, nothing built; at
// the attempt ceiling the deploy is parked instead of requeued forever.
func TestAuthorizeDeployUnavailableParksAtTheCeiling(t *testing.T) {
	r := newRig(t)
	r.maxAttempts = 4
	rec := r.started()
	r.auth.set(func(store.Lease) (Decision, error) {
		return Decision{}, fmt.Errorf("%w: more than 1000 reviews: refusing a partial list", ErrUnavailable)
	}, nil)
	r.enqueue(store.JobDeploy)
	for attempt := int64(1); attempt < r.maxAttempts; attempt++ {
		r.step(rec)
		j := r.jobs()[0]
		wantNotBefore := r.now.Add(authorizeBackoff(attempt - 1)).UnixMilli()
		if j.Status != store.StatusQueued || j.Trust != store.TrustUnclassified || j.Attempts != attempt || j.NotBefore != wantNotBefore {
			t.Fatalf("attempt %d: %+v, want QUEUED unclassified, attempts %d, not_before %d", attempt, j, attempt, wantNotBefore)
		}
		if _, ok, err := r.queue.Acquire(context.Background(), r.now); err != nil || ok {
			t.Fatalf("attempt %d: acquired before its backoff: %v, %v", attempt, ok, err)
		}
		r.now = r.now.Add(authorizeBackoff(attempt - 1))
	}
	r.step(rec)
	if j := r.jobs()[0]; j.Status != store.StatusPendingApproval || j.Trust != store.TrustUnclassified {
		t.Fatalf("at the ceiling: %+v, want PENDING_APPROVAL", j)
	}
	if r.built() || r.auth.authorized != int(r.maxAttempts) {
		t.Fatalf("built %v, authorized %d times", r.built(), r.auth.authorized)
	}
	if _, ok, err := r.queue.Acquire(context.Background(), r.now.Add(24*time.Hour)); err != nil || ok {
		t.Fatalf("a parked deploy was acquired again: %v, %v", ok, err)
	}
}

// A2-6: while GHES is unavailable, a running version built on an approval
// the database no longer holds live (here revoked by a push) is removed
// before the new deploy is requeued; a trusted version is left running.
func TestAuthorizeDeployUnavailableRemovesARevokedVersion(t *testing.T) {
	const pushed = "fedcba9876543210fedcba9876543210fedcba98"
	for _, approved := range []bool{true, false} {
		t.Run(fmt.Sprintf("built on an approval=%v", approved), func(t *testing.T) {
			r := newRig(t)
			rec := r.started()
			if approved {
				r.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
				r.auth.set(r.untrusted(false), nil)
			}
			r.enqueue(store.JobDeploy)
			r.drain(rec)
			if !r.running() {
				t.Fatal("not running")
			}
			r.auth.set(func(store.Lease) (Decision, error) {
				return Decision{}, fmt.Errorf("%w: connection refused", ErrUnavailable)
			}, nil)
			r.enqueueCommit(store.JobDeploy, pushed) // revokes every other commit (new_head)
			r.step(rec)
			if j := r.jobs()[1]; j.Status != store.StatusQueued || j.Attempts != 1 {
				t.Fatalf("the push = %+v, want requeued", j)
			}
			if r.running() == approved {
				t.Fatalf("running = %v after the outage, want %v", r.running(), !approved)
			}
		})
	}
}

// The approval the authorizer confirmed must be the one Classify audits: a
// grant recorded between the GHES read and the record requeues the deploy
// unclassified, and the next attempt deploys on the newest grant.
func TestAuthorizeDeployRequeuesWhenTheApprovalChanged(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
	confirm := r.untrusted(false)
	first := true
	r.auth.set(func(l store.Lease) (Decision, error) {
		d, err := confirm(l)
		if first {
			first = false
			r.approve(store.ApprovalViaReview, 200, "second", 8) // not re-read on GHES
		}
		return d, err
	}, nil)
	r.enqueue(store.JobDeploy)
	r.step(rec)
	if j := r.jobs()[0]; j.Status != store.StatusQueued || j.Trust != store.TrustUnclassified || j.Attempts != 1 {
		t.Fatalf("after a changed approval: %+v, want requeued unclassified", j)
	}
	if r.built() {
		t.Fatal("built on an approval that was not the newest")
	}
	r.now = r.now.Add(authorizeBackoff(0))
	r.step(rec)
	if j := r.jobs()[0]; j.Status != store.StatusSuccess || j.Trust != store.TrustUntrusted {
		t.Fatalf("second attempt: %+v", j)
	}
}

// D-V1-5, V1-I4: an opener downgraded while a trusted environment runs is
// torn down within one re-validation interval, by the running loop.
func TestRevalidatorTearsDownADowngradedTrustedOpenerWithinOneInterval(t *testing.T) {
	r := newRig(t)
	r.interval, r.grace = 400*time.Millisecond, time.Hour
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	if !r.running() || r.jobs()[0].Trust != store.TrustTrusted {
		t.Fatalf("trusted version not running: %+v", r.jobs())
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { rec.Run(ctx, 1) })
	wg.Go(func() { rec.Revalidate(ctx) })
	defer func() {
		cancel()
		wg.Wait()
	}()

	downgraded := time.Now()
	r.auth.set(nil, func(j store.Job) error {
		if j.Trust != store.TrustTrusted {
			return fmt.Errorf("unexpected builder trust %s", j.Trust)
		}
		return refuse("", "opener lead-dev#4242 now has read permission")
	})
	deadline := downgraded.Add(r.interval + 300*time.Millisecond) // one interval, plus scheduling slack
	for r.running() {
		if time.Now().After(deadline) {
			t.Fatalf("still running %s after the downgrade (interval %s)", time.Since(downgraded), r.interval)
		}
		time.Sleep(5 * time.Millisecond)
	}
	var teardown store.Job
	for _, j := range r.jobs() {
		if j.Type == store.JobTeardown {
			teardown = j
		}
	}
	if teardown.Origin != store.OriginRevalidation {
		t.Fatalf("no re-validation teardown: %+v", r.jobs())
	}
	if r.stager.staged[testEnv] || len(r.routeFiles()) != 0 {
		t.Fatalf("leftovers: staged %v routes %v", r.stager.staged, r.routeFiles())
	}
}

// A revoked approval tears the untrusted environment down with its reason,
// and the approval is revoked in the same transaction as the teardown.
func TestRevalidatorRevokesALostApproval(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
	r.auth.set(r.untrusted(false), nil)
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	r.auth.set(nil, func(store.Job) error {
		return refuse(store.RevokedDismissed, "review 100 is DISMISSED")
	})
	rec.revalidateOnce(context.Background(), map[string]*streak{})
	jobs := r.jobs()
	if j := jobs[len(jobs)-1]; j.Type != store.JobTeardown || j.Origin != store.OriginRevalidation || j.Status != store.StatusQueued {
		t.Fatalf("latest job %+v, want a queued re-validation teardown", j)
	}
	if live, err := r.queue.ApprovalLive(context.Background(), testEnv, authCommit); err != nil || live {
		t.Fatalf("approval still live: %v, %v", live, err)
	}
	r.drain(rec)
	if r.running() {
		t.Fatal("the revoked environment still runs")
	}
}

// V1-I4 grace: an environment GHES cannot verify is kept until it has been
// unverifiable for the grace period, then torn down; a success in between
// starts a new streak. An authorized environment is never touched.
func TestRevalidatorGracePeriod(t *testing.T) {
	r := newRig(t)
	r.interval, r.grace = 10*time.Minute, 30*time.Minute
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	down := true
	r.auth.set(nil, func(store.Job) error {
		if down {
			return fmt.Errorf("%w: connection refused", ErrUnavailable)
		}
		return nil
	})
	failing := map[string]*streak{}
	teardowns := func() int {
		n := 0
		for _, j := range r.jobs() {
			if j.Type == store.JobTeardown {
				n++
			}
		}
		return n
	}
	start := r.now
	for _, tc := range []struct {
		at        time.Duration
		down      bool
		teardowns int
	}{
		{0, true, 0}, {10 * time.Minute, true, 0}, {20 * time.Minute, true, 0},
		{25 * time.Minute, false, 0}, // recovered: the streak ends
		{30 * time.Minute, true, 0}, {50 * time.Minute, true, 0},
		{60 * time.Minute, true, 1}, // 30 minutes unverifiable
	} {
		r.now, down = start.Add(tc.at), tc.down
		rec.revalidateOnce(context.Background(), failing)
		if got := teardowns(); got != tc.teardowns {
			t.Fatalf("at +%s (down %v): %d teardowns, want %d", tc.at, tc.down, got, tc.teardowns)
		}
	}
	if len(failing) != 0 {
		t.Fatalf("streak kept after the teardown: %v", failing)
	}
	jobs := r.jobs()
	if j := jobs[len(jobs)-1]; j.Origin != store.OriginRevalidation {
		t.Fatalf("teardown %+v", j)
	}
}

// After a reboot wiped its staged secrets, an untrusted environment comes
// back only through AuthorizeDeploy: without a live approval it is parked,
// never rebuilt.
func TestRebootRebuildsAnUntrustedEnvironmentOnlyWithAnApproval(t *testing.T) {
	for _, approved := range []bool{true, false} {
		t.Run(fmt.Sprintf("approved=%v", approved), func(t *testing.T) {
			r := newRig(t)
			rec := r.started()
			r.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
			r.auth.set(r.untrusted(false), nil)
			r.enqueue(store.JobDeploy)
			r.drain(rec)
			if !approved {
				// Dismissed on GHES while the host was down; the dismissal
				// webhook was lost, so the DB grant is still live.
				r.auth.set(func(store.Lease) (Decision, error) {
					return Decision{}, refuse(store.RevokedDismissed, "review 100 is DISMISSED")
				}, nil)
			}
			r.crash()
			r.stager.staged = map[string]bool{} // ramfs wiped by the reboot
			r.engine.calls = nil
			before := r.auth.authorized
			rec = r.started()
			jobs := r.drain(rec)
			if r.auth.authorized != before+1 {
				t.Fatalf("the re-armed deploy skipped AuthorizeDeploy (%d calls)", r.auth.authorized-before)
			}
			last := jobs[len(jobs)-1]
			switch {
			case approved && (last.Status != store.StatusSuccess || last.Trust != store.TrustUntrusted || !r.running()):
				t.Fatalf("approved: %+v running %v", last, r.running())
			case !approved && (last.Status != store.StatusPendingApproval || r.running() || slices.Contains(r.engine.calls, "build")):
				t.Fatalf("not approved: %+v running %v calls %v", last, r.running(), r.engine.calls)
			}
		})
	}
}

// The grace is counted in checks as well as in time: with grace equal to
// the interval, the second consecutive failure tears down even when it
// returns a little less than one interval after the first (E2E finding:
// otherwise jitter costs a whole extra interval).
func TestRevalidatorGraceIgnoresJitter(t *testing.T) {
	r := newRig(t)
	r.interval, r.grace = time.Minute, time.Minute
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	r.auth.set(nil, func(store.Job) error { return fmt.Errorf("%w: connection refused", ErrUnavailable) })
	failing := map[string]*streak{}
	rec.revalidateOnce(context.Background(), failing)
	r.now = r.now.Add(time.Minute - 100*time.Millisecond) // the first check returned late
	rec.revalidateOnce(context.Background(), failing)
	jobs := r.jobs()
	if j := jobs[len(jobs)-1]; j.Type != store.JobTeardown || j.Origin != store.OriginRevalidation {
		t.Fatalf("second consecutive failure kept the environment: %+v", j)
	}
}

func TestStreakExhausted(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		interval, grace time.Duration
		failures        int64
		elapsed         time.Duration
		want            bool
	}{
		{time.Minute, time.Minute, 1, 0, false},
		{time.Minute, time.Minute, 2, 59 * time.Second, true},
		{10 * time.Minute, 30 * time.Minute, 3, 20 * time.Minute, false},
		{10 * time.Minute, 30 * time.Minute, 4, 29 * time.Minute, true},
		{10 * time.Minute, 25 * time.Minute, 4, 25 * time.Minute, true}, // ceil(25/10) = 3 intervals
		{10 * time.Minute, 25 * time.Minute, 3, 24 * time.Minute, false},
		{10 * time.Minute, 30 * time.Minute, 2, 30 * time.Minute, true}, // passes ran late: wall time decides
	} {
		s := &streak{since: t0, failures: tc.failures}
		if got := s.exhausted(t0.Add(tc.elapsed), tc.interval, tc.grace); got != tc.want {
			t.Errorf("%+v: exhausted = %v", tc, got)
		}
	}
}
