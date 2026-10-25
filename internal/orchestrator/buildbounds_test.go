package orchestrator

// Build bounds in the reconciler (E2b, D-V1-4, V1-I12): at most
// MaxConcurrentBuilds builds in flight across every worker, and a build
// past BuildTimeout is cancelled and fails its deploy (failure = 'build').

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
)

// enqueueEnv queues a deploy of env, as enqueueCommit does for testEnv.
func (r *rig) enqueueEnv(env string) {
	r.t.Helper()
	r.seq++
	id := fmt.Sprintf("%s-delivery-%d", env, r.seq)
	sum := sha256.Sum256([]byte(id))
	v, _, err := r.queue.Enqueue(context.Background(), store.Delivery{
		ID: id, PayloadSHA256: hex.EncodeToString(sum[:]), EnvID: env, Type: store.JobDeploy, Seq: r.seq,
		Source: store.Source{Repo: "acme/app", HeadRepo: "acme/app", PRNumber: 7, OpenerLogin: "opener", OpenerID: 4242,
			CommitSHA: "0123456789abcdef0123456789abcdef01234567", CloneURL: "https://git.example.internal/acme/app.git"},
		ReceivedAt: r.now,
	})
	if err != nil || v != store.VerdictAccepted {
		r.t.Fatalf("enqueue %s: %s, %v", env, v, err)
	}
}

// overlap is a build hook that records the most builds in flight at once.
// Each build waits up to 300 ms for a second one to start, so two builds
// that may overlap do.
type overlap struct {
	mu       sync.Mutex
	inFlight int
	peak     int
	arrived  chan struct{}
}

func newOverlap() *overlap { return &overlap{arrived: make(chan struct{}, 16)} }

func (o *overlap) build(ctx context.Context) error {
	o.mu.Lock()
	o.inFlight++
	o.peak = max(o.peak, o.inFlight)
	o.mu.Unlock()
	o.arrived <- struct{}{}
	defer func() {
		o.mu.Lock()
		o.inFlight--
		o.mu.Unlock()
	}()
	t := time.NewTimer(300 * time.Millisecond)
	defer t.Stop()
	for {
		o.mu.Lock()
		both := o.inFlight >= 2
		o.mu.Unlock()
		if both {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Two workers, two environments: with the default of one build at a time
// the builds never overlap; with two slots they do (the control: the hook
// can see an overlap).
func TestBuildsShareTheConcurrencyLimit(t *testing.T) {
	for _, tc := range []struct {
		slots, wantPeak int
	}{{0, 1}, {1, 1}, {2, 2}} {
		t.Run(fmt.Sprint(tc.slots), func(t *testing.T) {
			r := newRig(t)
			r.maxBuilds = tc.slots
			r.fastClock() // a deploy that finds the slot taken is requeued
			o := newOverlap()
			r.engine.buildHook = o.build
			rec := r.started()
			r.enqueueEnv("pr-7-0a0a0a0a0a")
			r.enqueueEnv("pr-8-0b0b0b0b0b")
			jobs := r.drainWith(rec, 2)
			for _, j := range jobs {
				if j.Status != store.StatusSuccess {
					t.Fatalf("job %+v, want SUCCESS", j)
				}
			}
			if o.peak != tc.wantPeak {
				t.Fatalf("%d builds in flight at once with %d slots, want %d", o.peak, tc.slots, tc.wantPeak)
			}
		})
	}
}

// A build still running at the timeout is cancelled: the engine sees its
// context end, the deploy rolls back and records FAILED (failure =
// 'build'), and the slot is released for the next build.
func TestBuildTimeoutCancelsAndFailsTheDeploy(t *testing.T) {
	r := newRig(t)
	r.buildTimeout = 50 * time.Millisecond
	var mu sync.Mutex
	var seen []error
	hang := true
	r.engine.buildHook = func(ctx context.Context) error {
		mu.Lock()
		h := hang
		mu.Unlock()
		if !h {
			return nil
		}
		<-ctx.Done()
		mu.Lock()
		seen = append(seen, ctx.Err())
		mu.Unlock()
		return fmt.Errorf("build stream: %w", ctx.Err())
	}
	rec := r.started()
	r.enqueue(store.JobDeploy)
	jobs := r.drain(rec)
	if j := jobs[len(jobs)-1]; j.Status != store.StatusFailed || j.Failure != store.FailureBuild {
		t.Fatalf("job %+v, want FAILED with failure build", j)
	}
	mu.Lock()
	if len(seen) != 1 || !errors.Is(seen[0], context.DeadlineExceeded) {
		t.Fatalf("engine saw %v, want its build context cancelled at the deadline", seen)
	}
	hang = false
	mu.Unlock()
	if len(r.engine.envs) != 0 || len(r.stager.staged) != 0 || len(r.routeFiles()) != 0 {
		t.Fatalf("leftovers: engine %v staged %v routes %v", r.engine.envs, r.stager.staged, r.routeFiles())
	}

	// The slot was released: the next deploy builds and succeeds.
	r.enqueueCommit(store.JobDeploy, "1123456789abcdef0123456789abcdef01234567")
	if jobs := r.drain(rec); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("next deploy = %+v, want SUCCESS", jobs[len(jobs)-1])
	}
}

// Fail closed: an engine that ignores the cancellation and reports success
// after the deadline still fails the deploy. A cancelled build is never
// read as a success.
func TestBuildPastTheTimeoutNeverSucceeds(t *testing.T) {
	r := newRig(t)
	r.buildTimeout = 20 * time.Millisecond
	r.engine.buildHook = func(context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	}
	rec := r.started()
	r.enqueue(store.JobDeploy)
	jobs := r.drain(rec)
	if j := jobs[len(jobs)-1]; j.Status != store.StatusFailed || j.Failure != store.FailureBuild {
		t.Fatalf("job %+v, want FAILED with failure build", j)
	}
	if r.running() {
		t.Fatal("the environment runs a build that passed its deadline")
	}
}

// fastClock runs 1,000 times faster than the wall clock from the rig's now,
// so a deploy requeued with a backoff of seconds is due again within
// milliseconds. Read-only after creation: safe for every worker.
func (r *rig) fastClock() {
	start, base := time.Now(), r.now
	r.clock = func() time.Time { return base.Add(time.Since(start) * 1000) }
}

// A deploy that finds every slot taken is requeued unclassified, nothing of
// it reaching the engine (E2b); once a slot frees it is leased again, builds
// and succeeds, and its slot is released at the end.
func TestDeployRequeuedOnSaturatedSlotsRunsWhenASlotFrees(t *testing.T) {
	r := newRig(t)
	r.fastClock()
	rec := r.started()
	rec.builds <- struct{}{} // the only slot is taken
	r.enqueue(store.JobDeploy)

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

	deadline := time.Now().Add(5 * time.Second)
	for r.jobs()[0].Attempts < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("deploy %+v, want it requeued again and again while the slot is taken", r.jobs()[0])
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.auth.mu.Lock()
	authorized := r.auth.authorized
	r.auth.mu.Unlock()
	if j := r.jobs()[0]; j.Status == store.StatusSuccess || r.built() || authorized != 0 {
		t.Fatalf("deploy %+v built %v authorized %d times without a slot", j, r.built(), authorized)
	}

	<-rec.builds // the build in flight ends
	for r.jobs()[0].Status != store.StatusSuccess {
		if time.Now().After(deadline) {
			t.Fatalf("deploy %+v, want SUCCESS once a slot is free", r.jobs()[0])
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(rec.builds); n != 0 {
		t.Fatalf("%d build slots taken after the deploy, want 0", n)
	}
}

// NewReconciler refuses build bounds and maintenance settings out of range.
func TestNewReconcilerRefusesInvalidBounds(t *testing.T) {
	for name, mutate := range map[string]func(*ReconcilerConfig){
		"negative builds":      func(c *ReconcilerConfig) { c.MaxConcurrentBuilds = -1 },
		"too many builds":      func(c *ReconcilerConfig) { c.MaxConcurrentBuilds = 17 },
		"negative timeout":     func(c *ReconcilerConfig) { c.BuildTimeout = -time.Second },
		"short retention":      func(c *ReconcilerConfig) { c.Retention = 23 * time.Hour },
		"negative retention":   func(c *ReconcilerConfig) { c.Retention = -time.Hour },
		"negative max age":     func(c *ReconcilerConfig) { c.DeliveryMaxAge = -time.Minute },
		"negative interval":    func(c *ReconcilerConfig) { c.PruneInterval = -time.Minute },
		"negative prune batch": func(c *ReconcilerConfig) { c.PruneBatch = -1 },
		"negative disk floor":  func(c *ReconcilerConfig) { c.MinFreeDiskBytes = -1 },
		"small disk floor":     func(c *ReconcilerConfig) { c.MinFreeDiskBytes = 1<<30 - 1 },
		"short TTL":            func(c *ReconcilerConfig) { c.EnvTTL = 59 * time.Minute },
		"negative TTL":         func(c *ReconcilerConfig) { c.EnvTTL = -time.Hour },
		"TTL set and disabled": func(c *ReconcilerConfig) { c.DisableTTL = true },
		"relative build dir":   func(c *ReconcilerConfig) { c.BuildDir = "tmp" },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			cfg := r.reconciler().cfg
			mutate(&cfg)
			if _, err := NewReconciler(cfg); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
	cfg := newRig(t).reconciler().cfg
	if cfg.MaxConcurrentBuilds != 1 || cfg.BuildTimeout != 20*time.Minute || cfg.Retention != 720*time.Hour ||
		cfg.DeliveryMaxAge != 15*time.Minute || cfg.PruneInterval != time.Hour ||
		cfg.MinFreeDiskBytes != 10240<<20 || cfg.EnvTTL != 168*time.Hour || cfg.DisableTTL {
		t.Fatalf("defaults = %+v", cfg)
	}
}
