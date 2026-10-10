package orchestrator

// Auto-cleanup (V1 F5, phase G, V1-I9): the free-disk floor, the build
// cache pruned around every build, the image prune after every teardown
// and every maintenance pass, the stale build directories removed at
// startup, and the TTL teardowns.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
)

// otherEnv is a second environment whose image the rig leaves behind.
const otherEnv = "pr-9-0b0b0b0b0b"

// audit is the audit trail as kind/detail, oldest first, after verifying
// the chain.
func (r *rig) audit() []string {
	r.t.Helper()
	ctx := context.Background()
	ar, err := store.OpenAuditReader(ctx, r.dbPath)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() {
		if err := ar.Close(); err != nil {
			r.t.Error(err)
		}
	}()
	var buf bytes.Buffer
	if _, err := ar.Export(ctx, &buf); err != nil {
		r.t.Fatal(err)
	}
	var out []string
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var rec store.AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, rec.Kind+"/"+rec.Detail)
	}
	if err := sc.Err(); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *rig) callCount(name string) int {
	r.engine.mu.Lock()
	defer r.engine.mu.Unlock()
	n := 0
	for _, c := range r.engine.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (r *rig) images() []string {
	r.engine.mu.Lock()
	defer r.engine.mu.Unlock()
	return slices.Sorted(maps.Keys(r.engine.images))
}

// The floor is a minimum: a build starts with exactly the floor free and
// is refused one byte below it, FAILED with failure = 'disk_floor', audited
// as deploy_refused, nothing built, nothing left on the host. Fail closed:
// a free space the engine cannot read refuses the build the same way.
func TestDeployRefusedBelowTheDiskFloor(t *testing.T) {
	const floor = 2 << 30
	for name, tc := range map[string]struct {
		free    int64
		freeErr error
		refused bool
	}{
		"at the floor":    {free: floor},
		"below the floor": {free: floor - 1, refused: true},
		"unknown":         {free: floor << 10, freeErr: errors.New("statfs: permission denied"), refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.minFreeDisk = floor
			r.engine.free = tc.free
			if tc.freeErr != nil {
				r.engine.fail["free-disk"] = tc.freeErr
			}
			rec := r.started()
			r.enqueue(store.JobDeploy)
			last := r.drain(rec)[0]
			if !tc.refused {
				if last.Status != store.StatusSuccess || !slices.Contains(r.audit(), "trusted_deploy/write_access") {
					t.Fatalf("job %+v, audit %v: want SUCCESS", last, r.audit())
				}
				return
			}
			if last.Status != store.StatusFailed || last.Failure != store.FailureDiskFloor {
				t.Fatalf("job %+v, want FAILED with failure disk_floor", last)
			}
			if got := r.audit(); !slices.Equal(got, []string{"trusted_deploy/write_access", "deploy_refused/disk_floor"}) {
				t.Fatalf("audit %v, want the classification then deploy_refused/disk_floor", got)
			}
			if r.callCount("build") != 0 || len(r.engine.built) != 0 {
				t.Fatalf("engine calls %v: a build ran below the floor", r.engine.calls)
			}
			if len(r.engine.envs) != 0 || len(r.stager.staged) != 0 || len(r.routeFiles()) != 0 {
				t.Fatalf("leftovers: engine %v staged %v routes %v", r.engine.envs, r.stager.staged, r.routeFiles())
			}
		})
	}
}

// No BuildKit state survives a build: the cache is pruned right after
// every build, successful or not, before the next one can start.
func TestBuildCachePrunedAfterEveryBuild(t *testing.T) {
	for name, buildErr := range map[string]error{"success": nil, "failure": errors.New("RUN false: exit 1")} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.engine.buildHook = func(context.Context) error { return buildErr }
			rec := r.started()
			r.enqueue(store.JobDeploy)
			if last := r.drain(rec)[0]; (last.Status == store.StatusSuccess) != (buildErr == nil) {
				t.Fatalf("job %+v", last)
			}
			r.engine.mu.Lock()
			defer r.engine.mu.Unlock()
			at := slices.Index(r.engine.calls, "build")
			if r.engine.cache != 0 || at < 0 || at+1 >= len(r.engine.calls) || r.engine.calls[at+1] != "prune-cache" {
				t.Fatalf("calls %v, cache %d: want prune-cache right after build, nothing left", r.engine.calls, r.engine.cache)
			}
		})
	}
}

// A prune that fails after a build leaves the cache dirty: the next build
// prunes first, and does not run while that prune fails (fail closed). The
// deploy whose build ran is not failed by it.
func TestBuildCachePruneFailureCleansBeforeTheNextBuild(t *testing.T) {
	r := newRig(t)
	pruneFails := errors.New("buildkit: prune failed")
	r.engine.buildHook = func(context.Context) error {
		r.engine.mu.Lock()
		defer r.engine.mu.Unlock()
		r.engine.fail["prune-cache"] = pruneFails
		return nil
	}
	rec := r.started()
	r.enqueueCommit(store.JobDeploy, "1123456789abcdef0123456789abcdef01234567")
	if last := lastOf(r.drain(rec)); last.Status != store.StatusSuccess {
		t.Fatalf("deploy with a failed prune after its build = %+v, want SUCCESS", last)
	}
	if r.engine.cache != 1 {
		t.Fatalf("cache %d, want the build's record left", r.engine.cache)
	}

	r.engine.buildHook = nil
	r.enqueueCommit(store.JobDeploy, "2223456789abcdef0123456789abcdef01234567")
	last := lastOf(r.drain(rec))
	if last.Status != store.StatusFailed || last.Failure != store.FailureBuild || r.callCount("build") != 1 {
		t.Fatalf("deploy while the cache cannot be pruned = %+v, %d builds; want FAILED/build, no build", last, r.callCount("build"))
	}

	r.engine.mu.Lock()
	delete(r.engine.fail, "prune-cache")
	r.engine.calls = nil
	r.engine.mu.Unlock()
	r.enqueueCommit(store.JobDeploy, "3323456789abcdef0123456789abcdef01234567")
	if last := lastOf(r.drain(rec)); last.Status != store.StatusSuccess {
		t.Fatalf("deploy after the prune recovered = %+v", last)
	}
	if want := []string{"destroy", "network", "prune-cache", "free-disk", "build", "prune-cache", "deploy"}; !slices.Equal(r.engine.calls, want) || r.engine.cache != 0 {
		t.Fatalf("calls %v, cache %d; want %v and nothing left", r.engine.calls, r.engine.cache, want)
	}

	// A clean cache is not pruned again before the next build.
	r.engine.calls = nil
	r.enqueueCommit(store.JobDeploy, "4423456789abcdef0123456789abcdef01234567")
	r.drain(rec)
	if want := []string{"destroy", "network", "free-disk", "build", "prune-cache", "deploy"}; !slices.Equal(r.engine.calls, want) {
		t.Fatalf("calls %v, want %v", r.engine.calls, want)
	}
}

func lastOf(jobs []store.Job) store.Job { return jobs[len(jobs)-1] }

// A teardown prunes the images of every environment gone from the host,
// its own and any other left behind, and keeps those still on the host.
func TestTeardownPrunesImages(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	r.engine.images[otherEnv] = 1 << 20
	r.engine.set(otherEnv, func(st *EngineState) { st.Running, st.Containers = true, 1 })

	r.enqueue(store.JobTeardown)
	if last := lastOf(r.drain(rec)); last.Status != store.StatusSuccess {
		t.Fatalf("teardown = %+v", last)
	}
	if got := r.images(); !slices.Equal(got, []string{otherEnv}) {
		t.Fatalf("images %v, want only %s, still on the host", got, otherEnv)
	}
	if keeps := r.engine.keeps; len(keeps) != 1 || !slices.Equal(keeps[0], []string{otherEnv}) {
		t.Fatalf("keep lists %v", keeps)
	}

	r.engine.set(otherEnv, func(st *EngineState) { *st = EngineState{} })
	delete(r.engine.envs, otherEnv)
	rec.cleanImages(context.Background(), rec.cfg.Logger)
	if got := r.images(); len(got) != 0 {
		t.Fatalf("images %v left once %s is gone", got, otherEnv)
	}
}

// An environment with a deploy in flight keeps its image, even before
// the engine reports it; once the deploy ends, an image left without an
// environment goes.
func TestImagePruneKeepsDeploysInFlight(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.engine.images[otherEnv] = 1 << 20
	rec.beginDeploy(otherEnv)
	if _, err := rec.pruneImages(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.images(); !slices.Equal(got, []string{otherEnv}) {
		t.Fatalf("images %v: the image of a deploy in flight was pruned", got)
	}
	rec.endDeploy(otherEnv)
	reclaimed, err := rec.pruneImages(context.Background())
	if err != nil || reclaimed != 1<<20 || len(r.images()) != 0 {
		t.Fatalf("after the deploy: reclaimed %d, %v, images %v", reclaimed, err, r.images())
	}
}

// Fail closed: without the host's view no image is pruned.
func TestImagePruneRefusesWithoutTheHostView(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.engine.images[otherEnv] = 1 << 20
	r.engine.fail["observe"] = errors.New("engine unreachable")
	if _, err := rec.pruneImages(context.Background()); err == nil {
		t.Fatal("image prune without the host view succeeded")
	}
	if r.callCount("prune-images") != 0 || len(r.images()) != 1 {
		t.Fatalf("calls %v, images %v: pruned without the host view", r.engine.calls, r.images())
	}
}

// Every maintenance pass ends with an image prune.
func TestMaintainPrunesImages(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.engine.images[otherEnv] = 1 << 20
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Maintain(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.images()) != 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Maintain pruned no image")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// Startup removes the build directories a crash left, and only those: a
// file or a link of the same name, and any other entry, stay; a link's
// target is never followed.
func TestStartupRemovesStaleBuildDirs(t *testing.T) {
	r := newRig(t)
	stale := filepath.Join(r.buildDir, buildDirPrefix+"123")
	if err := writeCheckout(filepath.Join(stale, "src"), testDockerfile); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	keep := filepath.Join(target, "keep")
	if err := os.WriteFile(keep, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(r.buildDir, buildDirPrefix+"link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(r.buildDir, buildDirPrefix+"file")
	other := filepath.Join(r.buildDir, "other-build-1")
	for _, p := range []string{file, other} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.started()
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale build dir: %v, want removed", err)
	}
	for _, p := range []string{link, file, other, keep} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s: %v, want kept", p, err)
		}
	}
	// A deploy's build directory never outlives it.
	r.enqueue(store.JobDeploy)
	r.drain(r.reconciler())
	entries, err := os.ReadDir(r.buildDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("build dir holds %d entries after a deploy, want the 3 kept", len(entries))
	}
}

// Fail closed: a build directory that cannot be read refuses the start.
func TestStartupRefusesAnUnreadableBuildDir(t *testing.T) {
	r := newRig(t)
	r.buildDir = filepath.Join(r.buildDir, "missing")
	if err := r.reconciler().Startup(context.Background()); err == nil {
		t.Fatal("Startup with a missing build directory succeeded")
	}
}

// G3: an environment whose running version is older than the TTL gets an
// internal teardown (origin ttl, audited ttl_expired), pinned to its
// commit; a younger one does not; a later push deploys again.
func TestTTLTearsDownExpiredEnvironments(t *testing.T) {
	r := newRig(t)
	r.envTTL = 2 * time.Hour
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)

	r.now = r.now.Add(2*time.Hour - time.Millisecond)
	rec.expireOnce(context.Background())
	if jobs := r.jobs(); len(jobs) != 1 {
		t.Fatalf("jobs %+v: a teardown queued before the TTL", jobs)
	}

	r.now = r.now.Add(time.Millisecond)
	rec.expireOnce(context.Background())
	jobs := r.jobs()
	td := lastOf(jobs)
	if len(jobs) != 2 || td.Type != store.JobTeardown || td.Origin != store.OriginTTL || td.Status != store.StatusQueued ||
		td.Source.CommitSHA != jobs[0].Source.CommitSHA {
		t.Fatalf("jobs %+v, want a queued ttl teardown of the running commit", jobs)
	}
	if got := r.audit(); !slices.Equal(got, []string{"trusted_deploy/write_access", "ttl_expired/ttl"}) {
		t.Fatalf("audit %v", got)
	}
	// Queued once: the teardown is now the latest job.
	rec.expireOnce(context.Background())
	if n := len(r.jobs()); n != 2 {
		t.Fatalf("%d jobs: the TTL teardown was queued twice", n)
	}
	if last := lastOf(r.drain(rec)); last.Status != store.StatusSuccess || r.running() || len(r.routeFiles()) != 0 {
		t.Fatalf("after the TTL teardown: %+v running %v routes %v", last, r.running(), r.routeFiles())
	}

	r.seq = td.Seq
	r.enqueue(store.JobDeploy)
	if last := lastOf(r.drain(rec)); last.Status != store.StatusSuccess || !r.running() {
		t.Fatalf("a later push = %+v, running %v; want deployed again", last, r.running())
	}
}

// The TTL leaves alone what it must: a failed deploy (nothing runs), an
// environment torn down, and everything when it is disabled.
func TestTTLSkipsWhatDoesNotRun(t *testing.T) {
	t.Run("failed deploy", func(t *testing.T) {
		r := newRig(t)
		r.fetchErr = errors.New("fetch failed")
		rec := r.started()
		r.enqueue(store.JobDeploy)
		r.drain(rec)
		r.now = r.now.Add(365 * 24 * time.Hour)
		rec.expireOnce(context.Background())
		if n := len(r.jobs()); n != 1 {
			t.Fatalf("%d jobs: a TTL teardown of a failed deploy", n)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		r := newRig(t)
		r.disableTTL = true
		rec := r.started()
		r.enqueue(store.JobDeploy)
		r.drain(rec)
		r.now = r.now.Add(365 * 24 * time.Hour)
		rec.expireOnce(context.Background())
		if n := len(r.jobs()); n != 1 || !r.running() {
			t.Fatalf("%d jobs, running %v: the disabled TTL tore down", n, r.running())
		}
	})
}

// The TTL pass runs inside Maintain, with the fake clock past the TTL.
func TestMaintainQueuesTTLTeardowns(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	r.now = r.now.Add(168 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Maintain(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for lastOf(r.jobs()).Origin != store.OriginTTL {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Maintain queued no TTL teardown")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// G leftover: a deploy parked for an approval that never comes expires
// with the TTL, counted from its creation: a TTL teardown of its commit
// supersedes it (SKIPPED), audited ttl_expired; nothing is built.
func TestTTLExpiresParkedDeploys(t *testing.T) {
	r := newRig(t)
	r.envTTL = 2 * time.Hour
	rec := r.started()
	r.auth.set(func(store.Lease) (Decision, error) {
		return Decision{}, refuse("", "fork without approval")
	}, nil)
	r.enqueue(store.JobDeploy)
	parked := lastOf(r.drain(rec))
	if parked.Status != store.StatusPendingApproval {
		t.Fatalf("deploy = %+v, want PENDING_APPROVAL", parked)
	}

	r.now = r.now.Add(2*time.Hour - time.Millisecond)
	rec.expireOnce(context.Background())
	if n := len(r.jobs()); n != 1 {
		t.Fatalf("%d jobs: a parked deploy expired before its TTL", n)
	}
	r.now = r.now.Add(time.Millisecond)
	rec.expireOnce(context.Background())
	td := lastOf(r.jobs())
	if td.Type != store.JobTeardown || td.Origin != store.OriginTTL || td.Source.CommitSHA != parked.Source.CommitSHA {
		t.Fatalf("jobs %+v, want a ttl teardown of the parked commit", r.jobs())
	}
	if got := r.audit(); !slices.Equal(got, []string{"deploy_refused/not_approved", "ttl_expired/ttl"}) {
		t.Fatalf("audit %v", got)
	}
	jobs := r.drain(rec)
	if jobs[0].Status != store.StatusSkipped || lastOf(jobs).Status != store.StatusSuccess {
		t.Fatalf("jobs %+v, want the parked deploy SKIPPED and the teardown SUCCESS", jobs)
	}
	if r.built() || r.running() {
		t.Fatal("the expired parked deploy was built or runs")
	}
	rec.expireOnce(context.Background())
	if n := len(r.jobs()); n != 2 {
		t.Fatalf("%d jobs: the TTL teardown was queued twice", n)
	}
}
