package orchestrator

// Maintain (V1 F3): the prune loop passes the builders the engine reports
// to Prune, and prunes nothing when it cannot read them.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
)

// prunable runs three deploys of testEnv: jobs 1 and 2 succeed, job 3
// fails at fetch and its rollback removes the environment. The engine is
// then left reporting the version job 2 built, as after a rollback that
// could not remove it.
func (r *rig) prunable(rec *Reconciler) {
	r.t.Helper()
	r.enqueueCommit(store.JobDeploy, "1123456789abcdef0123456789abcdef01234567")
	r.drain(rec)
	r.enqueueCommit(store.JobDeploy, "2223456789abcdef0123456789abcdef01234567")
	r.drain(rec)
	r.fetchErr = errors.New("fetch failed")
	r.enqueueCommit(store.JobDeploy, "3323456789abcdef0123456789abcdef01234567")
	if jobs := r.drain(rec); lastStatus(jobs) != store.StatusFailed {
		r.t.Fatalf("job 3 = %+v, want FAILED", jobs[len(jobs)-1])
	}
	r.engine.set(testEnv, func(st *EngineState) { st.Running, st.Containers, st.JobID = true, 1, 2 })
}

func jobIDs(jobs []store.Job) []int64 {
	var ids []int64
	for _, j := range jobs {
		ids = append(ids, j.ID)
	}
	return ids
}

// A pass past the retention prunes job 1 and keeps job 2, whose version
// the engine reports (the builder, A1-6), and job 3, the latest.
func TestPruneKeepsTheBuildersTheEngineReports(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.prunable(rec)
	r.now = r.now.Add(31 * 24 * time.Hour)
	stats, err := rec.prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := jobIDs(r.jobs()); !slices.Equal(got, []int64{2, 3}) || stats.Jobs != 1 {
		t.Fatalf("jobs %v left (stats %+v), want the builder 2 and the latest 3", got, stats)
	}
}

// Fail closed: when the engine cannot be observed, the pass prunes
// nothing, since it does not know which builders the sweep needs.
func TestPruneRefusesWithoutTheHostView(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.prunable(rec)
	r.now = r.now.Add(31 * 24 * time.Hour)
	r.engine.fail["observe"] = errors.New("engine unreachable")
	if _, err := rec.prune(context.Background()); err == nil {
		t.Fatal("prune without the host view succeeded")
	}
	if got := jobIDs(r.jobs()); !slices.Equal(got, []int64{1, 2, 3}) {
		t.Fatalf("jobs %v left, want all three", got)
	}
}

// Maintain runs a pass at once and then every interval, and returns when
// its context ends.
func TestMaintainRunsPassesUntilCancelled(t *testing.T) {
	r := newRig(t)
	r.pruneInterval = 5 * time.Millisecond
	rec := r.started()
	r.prunable(rec)
	r.now = r.now.Add(31 * 24 * time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rec.Maintain(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Equal(jobIDs(r.jobs()), []int64{2, 3}) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("jobs %v: no prune pass ran", jobIDs(r.jobs()))
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Later passes keep running: each ends with one image prune.
	imagePrunes := func() int {
		r.engine.mu.Lock()
		defer r.engine.mu.Unlock()
		n := 0
		for _, c := range r.engine.calls {
			if c == "prune-images" {
				n++
			}
		}
		return n
	}
	before := imagePrunes()
	for imagePrunes() <= before+1 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Maintain stopped after its first passes")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Maintain did not return after cancellation")
	}
}
