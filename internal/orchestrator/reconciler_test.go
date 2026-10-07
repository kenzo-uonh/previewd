package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// hostEngine is a fake Docker host.
type hostEngine struct {
	mu    sync.Mutex
	envs  map[string]EngineState
	fail  map[string]error // step -> error
	calls []string
}

func newHostEngine() *hostEngine {
	return &hostEngine{envs: map[string]EngineState{}, fail: map[string]error{}}
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

func (h *hostEngine) Build(context.Context, string, string) error { return h.step("build") }

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

// memStager is a fake secret stager.
type memStager struct {
	mu      sync.Mutex
	staged  map[string]bool
	failErr error
	listErr error
}

func (m *memStager) Stage(env string, _ map[string]string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return "", m.failErr
	}
	m.staged[env] = true
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

type staticSecrets map[string]string

func (s staticSecrets) GetSecrets() map[string]string { return s }

type rig struct {
	t        *testing.T
	dbPath   string
	queue    *store.Store
	engine   *hostEngine
	stager   *memStager
	routes   RoutePublisher
	routeDir string
	fetchErr error
	now      time.Time
	seq      int64
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
	r := &rig{
		t: t, dbPath: filepath.Join(dir, "previewd.sqlite"),
		engine: newHostEngine(), stager: &memStager{staged: map[string]bool{}},
		routes: pub, routeDir: routeDir, now: time.UnixMilli(1_800_000_000_000),
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
		Secrets: staticSecrets{"TOKEN": "value"},
		Fetch: func(context.Context, string, string, string) error {
			return r.fetchErr
		},
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
	r.seq++
	id := string(rune('a'+r.seq)) + "-delivery"
	sum := sha256.Sum256([]byte(id))
	v, _, err := r.queue.Enqueue(context.Background(), store.Delivery{
		ID: id, PayloadSHA256: hex.EncodeToString(sum[:]), EnvID: testEnv, Type: typ, Seq: r.seq,
		Source: store.Source{Repo: "acme/app", PRNumber: 7, CommitSHA: "0123456789abcdef0123456789abcdef01234567", CloneURL: "https://git.example.internal/acme/app.git"},
	})
	if err != nil || v != store.VerdictAccepted {
		r.t.Fatalf("enqueue: %s, %v", v, err)
	}
}

// drain runs one worker until no job is QUEUED or IN_PROGRESS.
func (r *rig) drain(rec *Reconciler) []store.Job {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Run(ctx, 1)
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
	// ExecuteDeploy removes the previous version before building.
	if want := []string{"observe", "destroy", "network", "build", "deploy"}; !slices.Equal(r.engine.calls, want) {
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

// Any failing deploy step rolls back to absent and records FAILED: no route,
// container, network or staging survives.
func TestReconcilerDeployFailureRollsBack(t *testing.T) {
	for _, step := range []string{"fetch", "network", "build", "stage", "deploy", "publish"} {
		t.Run(step, func(t *testing.T) {
			r := newRig(t)
			boom := errors.New(step + " failed")
			switch step {
			case "fetch":
				r.fetchErr = boom
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
			if lastStatus(jobs) != store.StatusFailed {
				t.Fatalf("job = %+v, want FAILED", jobs)
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
