package store

// F1 (V1 spec, phase F): Prune scenarios. Each test names the property of
// V1-I6 it pins: an old redelivery stays stale, the latest job of every
// environment survives, non-terminal jobs survive, and no transaction
// deletes more than the batch.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// prunePast is a pass two days after t0 with a one-day retention: every
// row written at t0 is past it.
func prunePast(batch int, builders ...int64) PruneRequest {
	return PruneRequest{Now: t0.Add(48 * time.Hour), Retention: 24 * time.Hour,
		DeliveryMaxAge: 15 * time.Minute, Batch: batch, Builders: builders}
}

func prune(t *testing.T, s *Store, req PruneRequest) PruneStats {
	t.Helper()
	stats, err := s.Prune(context.Background(), req)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if stats.MaxBatch > int64(req.Batch) {
		t.Fatalf("Prune deleted %d rows in one transaction, batch %d", stats.MaxBatch, req.Batch)
	}
	return stats
}

func countRows(t *testing.T, s *Store, table string) int64 {
	t.Helper()
	var n int64
	// table is a constant of the calling test, never input.
	if err := s.db.QueryRowContext(context.Background(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// deliver enqueues d and returns its verdict and job.
func deliver(t *testing.T, s *Store, d Delivery) (Verdict, int64) {
	t.Helper()
	v, id, err := s.Enqueue(context.Background(), d)
	if err != nil {
		t.Fatalf("Enqueue %s: %v", d.ID, err)
	}
	return v, id
}

// F1: after pruning, a redelivery of a pruned delivery (GitHub keeps the
// GUID and the body) is stale, and so is a new delivery at a pruned seq.
// A newer delivery is still accepted: the stale rule did not close the
// environment.
func TestPruneOldRedeliveryIsStale(t *testing.T) {
	s, _ := sweptStore(t)
	d1, d2, d3 := testDelivery("d1", envA, JobDeploy, 1), testDelivery("d2", envA, JobDeploy, 2), testDelivery("d3", envA, JobTeardown, 3)
	deliver(t, s, d1)
	finish(t, s, acquire(t, s), StatusSuccess) // job 1
	deliver(t, s, d2)
	finish(t, s, acquire(t, s), StatusFailed) // job 2
	deliver(t, s, d3)                         // job 3, QUEUED, latest

	stats := prune(t, s, prunePast(500))
	if stats.Jobs != 2 || stats.Deliveries != 3 {
		t.Fatalf("stats %+v, want jobs 1 and 2 and every delivery pruned", stats)
	}
	if n := countRows(t, s, "deliveries"); n != 0 {
		t.Fatalf("%d deliveries left, want none: the redeliveries below must not be caught as replays", n)
	}
	for _, d := range []Delivery{d1, d2, d3, testDelivery("fresh-at-2", envA, JobDeploy, 2)} {
		d.ReceivedAt = t0.Add(48 * time.Hour)
		if v, id := deliver(t, s, d); v != VerdictStale || id != 0 {
			t.Fatalf("%s at pruned seq %d = %s/%d, want stale", d.ID, d.Seq, v, id)
		}
	}
	if v, _ := deliver(t, s, testDelivery("d4", envA, JobDeploy, 4)); v != VerdictAccepted {
		t.Fatalf("newer delivery = %s, want accepted", v)
	}
}

// F1: the stale rule reads max(jobs.seq, watermarks.seq). A watermark above
// every job makes a delivery between them stale; a job above the watermark
// does the same on the other side.
func TestStaleCheckReadsJobsAndWatermark(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO watermarks (preview_id, seq) VALUES (?, 10), (?, 10)`, envA, envB); err != nil {
		t.Fatal(err)
	}
	deliver(t, s, testDelivery("b12", envB, JobDeploy, 12))
	for _, tc := range []struct {
		d    Delivery
		want Verdict
	}{
		{testDelivery("a5", envA, JobDeploy, 5), VerdictStale},   // below the watermark, no job at all
		{testDelivery("a10", envA, JobDeploy, 10), VerdictStale}, // equal to it
		{testDelivery("a11", envA, JobDeploy, 11), VerdictAccepted},
		{testDelivery("b11", envB, JobDeploy, 11), VerdictStale}, // above the watermark, below job b12
		{testDelivery("b13", envB, JobDeploy, 13), VerdictAccepted},
	} {
		if v, _ := deliver(t, s, tc.d); v != tc.want {
			t.Errorf("%s (seq %d) = %s, want %s", tc.d.ID, tc.d.Seq, v, tc.want)
		}
	}
}

// F1: whatever their age and status, the job with the highest seq of each
// environment survives, and the watermark holds the highest seq pruned.
func TestPruneKeepsLatestJobPerEnvironment(t *testing.T) {
	s, _ := sweptStore(t)
	envs := []string{envA, envB, "pr-3-0c0c0c0c0c"}
	statuses := []JobStatus{StatusSuccess, StatusFailed, StatusSuccess, StatusFailed}
	latest := map[string]int64{}
	for i, env := range envs {
		for seq := int64(1); seq <= int64(len(statuses)+i); seq++ {
			deliver(t, s, testDelivery(fmt.Sprintf("%s-%d", env, seq), env, JobDeploy, seq))
			l := acquire(t, s)
			finish(t, s, l, statuses[int(seq)%len(statuses)])
			latest[env] = l.JobID
		}
	}

	prune(t, s, prunePast(2))
	jobs, err := s.Jobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, j := range jobs {
		if _, dup := got[j.EnvID]; dup {
			t.Fatalf("%s keeps more than one job: %+v", j.EnvID, jobs)
		}
		got[j.EnvID] = j.ID
	}
	for i, env := range envs {
		if got[env] != latest[env] {
			t.Errorf("%s keeps job %d, want its latest %d", env, got[env], latest[env])
		}
		var mark int64
		if err := s.db.QueryRowContext(context.Background(), `SELECT seq FROM watermarks WHERE preview_id = ?`, env).Scan(&mark); err != nil {
			t.Fatal(err)
		}
		if want := int64(len(statuses) + i - 1); mark != want {
			t.Errorf("watermark of %s = %d, want %d (the highest pruned seq)", env, mark, want)
		}
	}
}

// F1: QUEUED, IN_PROGRESS and PENDING_APPROVAL jobs are never pruned, even
// when they are not the latest of their environment and the retention is
// zero.
func TestPruneKeepsNonTerminalJobs(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	deliver(t, s, testDelivery("a1", envA, JobDeploy, 1))
	running := acquire(t, s) // envA job 1: IN_PROGRESS
	deliver(t, s, testDelivery("a2", envA, JobDeploy, 2))
	deliver(t, s, testDelivery("a3", envA, JobTeardown, 3)) // envA job 3: latest; job 2 QUEUED behind it
	deliver(t, s, testDelivery("b1", envB, JobDeploy, 1))
	parked := acquire(t, s) // envB job 4
	if parked.EnvID != envB {
		t.Fatalf("leased %+v, want envB's deploy", parked)
	}
	if err := s.Park(ctx, parked); err != nil {
		t.Fatal(err)
	}
	deliver(t, s, testDelivery("b2", envB, JobTeardown, 2)) // envB job 5: latest

	before := statuses(t, s)
	req := prunePast(1)
	req.Now, req.Retention = t0.Add(time.Hour), 0
	if stats := prune(t, s, req); stats.Jobs != 0 {
		t.Fatalf("pruned %d jobs, want none", stats.Jobs)
	}
	if after := statuses(t, s); !slices.Equal(after, before) {
		t.Fatalf("jobs %v after pruning, want %v", after, before)
	}
	want := []JobStatus{StatusInProgress, StatusQueued, StatusQueued, StatusPendingApproval, StatusQueued}
	if !slices.Equal(before, want) {
		t.Fatalf("setup: statuses %v, want %v", before, want)
	}
	if err := s.Finish(ctx, running, StatusSuccess, t0.Add(time.Hour)); err != nil {
		t.Fatalf("the IN_PROGRESS job lost its lease to Prune: %v", err)
	}
}

// pruneFixture holds more prunable rows of every kind than the batches
// below: 7 jobs, 8 deliveries, 7 approvals and 7 boots, plus 14 approval
// deliveries Prune must keep.
func pruneFixture(t *testing.T) *Store {
	t.Helper()
	s, _ := sweptStore(t)
	ctx := context.Background()
	for seq := int64(1); seq <= 8; seq++ {
		deliver(t, s, testDelivery(fmt.Sprintf("d%d", seq), envB, JobDeploy, seq))
		finish(t, s, acquire(t, s), StatusSuccess)
	}
	for i := range 7 {
		commit := fmt.Sprintf("%04x", i+1) + testSource.CommitSHA[4:]
		approve(t, s, grantOf(commit, int64(100+2*i)))
		revoke(t, s, commit, int64(101+2*i))
	}
	for range keptBoots + 6 { // the first sweep made one
		if _, err := s.StartupSweep(ctx, t0, nil); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// F1: no transaction deletes more rows than the batch, whatever the
// batch; a smaller batch only takes more transactions. The 14 approval
// deliveries stay: their seq is above MaxSeq of envA, which has no job, so
// a redelivery of one must still be caught as a replay.
func TestPruneBatchesNeverExceedTheLimit(t *testing.T) {
	for _, batch := range []int{1, 3, 7, 1000} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			s := pruneFixture(t)
			if n := countRows(t, s, "deliveries"); n != 22 {
				t.Fatalf("fixture holds %d deliveries, want 8 job deliveries and 14 approval ones", n)
			}
			stats := prune(t, s, prunePast(batch))
			want := PruneStats{Jobs: 7, Deliveries: 8, Approvals: 7, Boots: 7, MaxBatch: min(int64(batch), 8)}
			if stats != want {
				t.Fatalf("stats %+v, want %+v", stats, want)
			}
			if n := countRows(t, s, "deliveries"); n != 14 {
				t.Fatalf("%d deliveries left, want the 14 above MaxSeq", n)
			}
		})
	}
}

// F1: each batch step, on its own transaction, stops at the limit.
func TestPruneStepsStopAtTheBatch(t *testing.T) {
	s := pruneFixture(t)
	ctx := context.Background()
	cutoff := t0.Add(24 * time.Hour).UnixMilli()
	for name, step := range map[string]func(*sql.Tx) (int64, error){
		"jobs":       func(tx *sql.Tx) (int64, error) { return pruneJobs(ctx, tx, cutoff, "[]", 3) },
		"deliveries": func(tx *sql.Tx) (int64, error) { return pruneDeliveries(ctx, tx, cutoff, 3) },
		"approvals":  func(tx *sql.Tx) (int64, error) { return pruneApprovals(ctx, tx, cutoff, 3) },
		"boots":      func(tx *sql.Tx) (int64, error) { return pruneBoots(ctx, tx, 3) },
	} {
		var n int64
		if err := s.inTx(ctx, name, func(tx *sql.Tx) error {
			var err error
			n, err = step(tx)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n != 3 {
			t.Errorf("one %s batch deleted %d rows, want exactly the batch (3) of 7 or more eligible", name, n)
		}
	}
}

// Boots: the newest keptBoots epochs survive, so the next epoch stays above
// every lease ever handed out.
func TestPruneKeepsTheNewestBoots(t *testing.T) {
	s := pruneFixture(t)
	ctx := context.Background()
	prune(t, s, prunePast(2))
	var lo, hi, n int64
	if err := s.db.QueryRowContext(ctx, `SELECT min(epoch), max(epoch), count(*) FROM boots`).Scan(&lo, &hi, &n); err != nil {
		t.Fatal(err)
	}
	if n != keptBoots || hi != keptBoots+7 || lo != 8 {
		t.Fatalf("boots %d..%d (%d), want %d..%d", lo, hi, n, 8, keptBoots+7)
	}
	res, err := s.StartupSweep(ctx, t0, nil)
	if err != nil || res.Epoch != hi+1 {
		t.Fatalf("next epoch = %d (%v), want %d", res.Epoch, err, hi+1)
	}
}

// Fail records the step that failed; anything outside the vocabulary, and
// any teardown, is refused without a change.
func TestFailRecordsTheFailedStep(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	deliver(t, s, testDelivery("d1", envA, JobDeploy, 1))
	l := acquire(t, s)
	for _, f := range []Failure{FailureNone, FailureInterrupted, "timeout", "build "} {
		if err := s.Fail(ctx, l, f, t0); !errors.Is(err, ErrInvalidFailure) {
			t.Fatalf("Fail(%q) = %v, want ErrInvalidFailure", f, err)
		}
	}
	if st := statuses(t, s); !slices.Equal(st, []JobStatus{StatusInProgress}) {
		t.Fatalf("a refused Fail changed the job: %v", st)
	}
	if err := s.Fail(ctx, l, FailureBuild, t0); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Jobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if j := jobs[0]; j.Status != StatusFailed || j.Failure != FailureBuild || j.FinishedAt != t0.UnixMilli() {
		t.Fatalf("job %+v, want FAILED with failure build", j)
	}
	if err := s.Fail(ctx, l, FailureBuild, t0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("second Fail = %v, want ErrLeaseLost", err)
	}

	deliver(t, s, testDelivery("d2", envA, JobTeardown, 2))
	if err := s.Fail(ctx, acquire(t, s), FailureBuild, t0); !errors.Is(err, ErrTeardownCannotFail) {
		t.Fatalf("Fail on a teardown = %v, want ErrTeardownCannotFail", err)
	}
}

// F2 finding: the sweep's Keep reads the builder of an environment and
// every newer job. Builder 1 runs, deploy 2 was skipped by teardown 3,
// which failed and waits requeued: the sweep destroys the environment
// (job 2 executed nothing, but it is not QUEUED). Pruning job 2 must not
// turn that destroy into a keep.
func TestPruneKeepsWhatTheSweepReads(t *testing.T) {
	for _, pruned := range []bool{false, true} {
		s, path := sweptStore(t)
		ctx := context.Background()
		deliver(t, s, testDelivery("d1", envA, JobDeploy, 1))
		builder := acquire(t, s)
		finish(t, s, builder, StatusSuccess)
		deliver(t, s, testDelivery("d2", envA, JobDeploy, 2))
		deliver(t, s, testDelivery("d3", envA, JobTeardown, 3))
		if err := s.Requeue(ctx, acquire(t, s), t0); err != nil { // job 3; job 2 SKIPPED
			t.Fatal(err)
		}
		if pruned {
			req := prunePast(10, builder.JobID)
			req.Now, req.Retention = t0.Add(time.Hour), time.Minute
			if stats := prune(t, s, req); stats.Jobs != 0 {
				t.Fatalf("pruned %d jobs, want none: job 2 is newer than the builder", stats.Jobs)
			}
		}
		_, res := crashAndSweep(t, s, path, []Observation{intact(envA, builder.JobID)})
		if !slices.Equal(res.Destroy, []string{envA}) {
			t.Fatalf("pruned=%v: sweep destroys %v, want %s", pruned, res.Destroy, envA)
		}
	}
}

// F3: on a real file (modernc, WAL, auto_vacuum = INCREMENTAL), Prune hands
// the pages it freed back to the file system: the page count drops, no
// free page is left below incremental_vacuum's 1,000, and the file shrinks
// once the WAL is checkpointed.
func TestPruneShrinksTheFile(t *testing.T) {
	s, path := sweptStore(t)
	ctx := context.Background()
	deliver(t, s, testDelivery("top", envA, JobDeploy, 1_000_000))
	if _, err := s.db.ExecContext(ctx, `
		WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 4000)
		INSERT INTO deliveries (delivery_id, payload_sha256, preview_id, seq, verdict, received_at)
		SELECT 'bulk-' || i, printf('%064x', i), ?, i, 'stale', ? FROM n`, envA, t0.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	pages := func() (count, free, bytes int64) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&free); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return count, free, fi.Size()
	}
	before, _, sizeBefore := pages()

	if stats := prune(t, s, prunePast(500)); stats.Deliveries != 4001 {
		t.Fatalf("pruned %d deliveries, want 4001", stats.Deliveries)
	}
	after, free, sizeAfter := pages()
	if after >= before/2 || free != 0 || sizeAfter >= sizeBefore/2 {
		t.Fatalf("page count %d -> %d (%d free), file %d -> %d bytes: the freed pages were not reclaimed",
			before, after, free, sizeBefore, sizeAfter)
	}
	t.Logf("page count %d -> %d, file %d -> %d bytes", before, after, sizeBefore, sizeAfter)
}

// Prune pauses Yield before each transaction but the first, and stops at
// once when its context ends during a pause.
func TestPruneYieldsBetweenTransactions(t *testing.T) {
	s := pruneFixture(t)
	req := prunePast(1000)
	req.Yield = 20 * time.Millisecond
	start := time.Now()
	prune(t, s, req)
	// 4 steps of one batch each, then the vacuum: 4 pauses at least.
	if took := time.Since(start); took < 4*req.Yield {
		t.Fatalf("Prune took %s, want at least 4 yields of %s", took, req.Yield)
	}

	s = pruneFixture(t)
	req = prunePast(1)
	req.Yield = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	stats, err := s.Prune(ctx, req)
	if !errors.Is(err, context.DeadlineExceeded) || stats.Jobs != 1 {
		t.Fatalf("Prune = %+v, %v; want one batch, then the cancellation during the pause", stats, err)
	}
}
