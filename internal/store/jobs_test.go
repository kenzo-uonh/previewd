package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.UnixMilli(1_800_000_000_000)

const envA, envB = "pr-1-0a0a0a0a0a", "pr-2-0b0b0b0b0b"

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := NewStore(context.Background(), path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func sweptStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	s := openStore(t, path)
	if _, err := s.StartupSweep(context.Background(), t0, nil); err != nil {
		t.Fatalf("StartupSweep: %v", err)
	}
	return s, path
}

var testSource = Source{
	Repo:        "acme/app",
	HeadRepo:    "acme/app",
	PRNumber:    7,
	OpenerLogin: "opener",
	OpenerID:    4242,
	CommitSHA:   "0123456789abcdef0123456789abcdef01234567",
	CloneURL:    "https://git.example.internal/acme/app.git",
}

// payloadHash stands for the SHA-256 of a signed body; distinct deliveries
// carry distinct bodies.
func payloadHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func testDelivery(id, env string, typ JobType, seq int64) Delivery {
	return Delivery{ID: id, PayloadSHA256: payloadHash("body of " + id), EnvID: env, Type: typ, Seq: seq, Source: testSource, ReceivedAt: t0}
}

func enqueue(t *testing.T, s *Store, id, env string, typ JobType, seq int64) (Verdict, int64) {
	t.Helper()
	v, jobID, err := s.Enqueue(context.Background(), testDelivery(id, env, typ, seq))
	if err != nil {
		t.Fatalf("Enqueue %s: %v", id, err)
	}
	return v, jobID
}

func acquire(t *testing.T, s *Store) Lease {
	t.Helper()
	l, ok, err := s.Acquire(context.Background(), t0)
	if err != nil || !ok {
		t.Fatalf("Acquire = %v, %v", ok, err)
	}
	return l
}

func finish(t *testing.T, s *Store, l Lease, st JobStatus) {
	t.Helper()
	if err := s.Finish(context.Background(), l, st, t0); err != nil {
		t.Fatalf("Finish %d %s: %v", l.JobID, st, err)
	}
}

func statuses(t *testing.T, s *Store) []JobStatus {
	t.Helper()
	jobs, err := s.Jobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]JobStatus, len(jobs))
	for i, j := range jobs {
		out[i] = j.Status
	}
	return out
}

// Fail closed: before the startup sweep, the queue serves nothing.
func TestQueueRefusesBeforeSweep(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "previewd.sqlite"))
	ctx := context.Background()
	if _, _, err := s.Enqueue(ctx, testDelivery("d1", envA, JobDeploy, 1)); !errors.Is(err, ErrNotSwept) {
		t.Errorf("Enqueue: %v, want ErrNotSwept", err)
	}
	if _, _, err := s.Acquire(ctx, t0); !errors.Is(err, ErrNotSwept) {
		t.Errorf("Acquire: %v, want ErrNotSwept", err)
	}
	if err := s.Finish(ctx, Lease{JobID: 1, Type: JobDeploy}, StatusSuccess, t0); !errors.Is(err, ErrNotSwept) {
		t.Errorf("Finish: %v, want ErrNotSwept", err)
	}
	if err := s.Requeue(ctx, Lease{JobID: 1, Type: JobTeardown}, t0); !errors.Is(err, ErrNotSwept) {
		t.Errorf("Requeue: %v, want ErrNotSwept", err)
	}
}

func TestEnqueueRejectsInvalidDelivery(t *testing.T) {
	s, _ := sweptStore(t)
	long := strings.Repeat("a", 2049)
	for name, mutate := range map[string]func(d *Delivery){
		"empty id":           func(d *Delivery) { d.ID = "" },
		"id too long":        func(d *Delivery) { d.ID = long[:65] },
		"empty env":          func(d *Delivery) { d.EnvID = "" },
		"env too long":       func(d *Delivery) { d.EnvID = long[:64] },
		"unknown type":       func(d *Delivery) { d.Type = "rollback" },
		"type case varies":   func(d *Delivery) { d.Type = "Deploy" },
		"zero seq":           func(d *Delivery) { d.Seq = 0 },
		"negative seq":       func(d *Delivery) { d.Seq = -1 },
		"no payload hash":    func(d *Delivery) { d.PayloadSHA256 = "" },
		"short payload hash": func(d *Delivery) { d.PayloadSHA256 = d.PayloadSHA256[:63] },
		"upper payload hash": func(d *Delivery) { d.PayloadSHA256 = strings.ToUpper(d.PayloadSHA256) },
		"short repo":         func(d *Delivery) { d.Source.Repo = "a/" },
		"long repo":          func(d *Delivery) { d.Source.Repo = long[:141] },
		"zero pr":            func(d *Delivery) { d.Source.PRNumber = 0 },
		"short commit":       func(d *Delivery) { d.Source.CommitSHA = d.Source.CommitSHA[:39] },
		"non hex commit":     func(d *Delivery) { d.Source.CommitSHA = "g" + d.Source.CommitSHA[1:] },
		"no clone url":       func(d *Delivery) { d.Source.CloneURL = "" },
		"clone url too long": func(d *Delivery) { d.Source.CloneURL = long },
		"long head repo":     func(d *Delivery) { d.Source.HeadRepo = long[:141] },
		"no opener login":    func(d *Delivery) { d.Source.OpenerLogin = "" },
		"long opener login":  func(d *Delivery) { d.Source.OpenerLogin = long[:40] },
		"zero opener id":     func(d *Delivery) { d.Source.OpenerID = 0 },
		"no receipt time":    func(d *Delivery) { d.ReceivedAt = time.Time{} },
		"epoch receipt time": func(d *Delivery) { d.ReceivedAt = time.UnixMilli(0) },
	} {
		d := testDelivery("d", envA, JobDeploy, 1)
		mutate(&d)
		if _, _, err := s.Enqueue(context.Background(), d); !errors.Is(err, ErrInvalidDelivery) {
			t.Errorf("%s: %v, want ErrInvalidDelivery", name, err)
		}
	}
	if got := statuses(t, s); len(got) != 0 {
		t.Fatalf("invalid deliveries left jobs %v", got)
	}
}

// Replay protection: a redelivery changes nothing.
func TestEnqueueReplay(t *testing.T) {
	s, _ := sweptStore(t)
	if v, id := enqueue(t, s, "d1", envA, JobDeploy, 1); v != VerdictAccepted || id != 1 {
		t.Fatalf("first delivery = %s/%d", v, id)
	}
	if v, id := enqueue(t, s, "d1", envA, JobDeploy, 1); v != VerdictReplay || id != 0 {
		t.Fatalf("redelivery = %s/%d, want replay", v, id)
	}
	if got := statuses(t, s); len(got) != 1 {
		t.Fatalf("jobs after replay: %v", got)
	}
}

// GitHub does not sign X-GitHub-Delivery: the same signed body resent under
// a new ID (and a later timestamp) is a replay, not a new intent.
func TestEnqueueReplaysPayloadUnderNewID(t *testing.T) {
	s, _ := sweptStore(t)
	d := testDelivery("d1", envA, JobDeploy, 1)
	if v, _, err := s.Enqueue(context.Background(), d); err != nil || v != VerdictAccepted {
		t.Fatalf("first delivery = %s, %v", v, err)
	}
	forged := d
	forged.ID, forged.Seq = "d2", 99
	if v, id, err := s.Enqueue(context.Background(), forged); err != nil || v != VerdictReplay || id != 0 {
		t.Fatalf("same body under a new ID = %s/%d, %v; want replay", v, id, err)
	}
	jobs, err := s.Jobs(context.Background())
	if err != nil || len(jobs) != 1 || jobs[0].Source != testSource {
		t.Fatalf("jobs = %+v, %v", jobs, err)
	}
}

// D1: a newer intent supersedes an older delivery whatever its status, here
// FAILED. The plan's first rule (QUEUED/IN_PROGRESS/SUCCESS only) deployed
// the older commit.
func TestEnqueueStaleBehindFailedNewerDeploy(t *testing.T) {
	s, _ := sweptStore(t)
	enqueue(t, s, "d2", envA, JobDeploy, 2)
	finish(t, s, acquire(t, s), StatusFailed)
	if v, id := enqueue(t, s, "d1", envA, JobDeploy, 1); v != VerdictStale || id != 0 {
		t.Fatalf("older delivery after a failed newer deploy = %s/%d, want stale", v, id)
	}
	if v, _ := enqueue(t, s, "d1b", envA, JobTeardown, 2); v != VerdictStale {
		t.Fatalf("equal seq = %s, want stale", v)
	}
	// Other environments are independent.
	if v, _ := enqueue(t, s, "d3", envB, JobDeploy, 1); v != VerdictAccepted {
		t.Fatalf("other environment = %s, want accepted", v)
	}
}

// AcquireJob: the newest queued intent wins, older ones are SKIPPED in the
// same transaction, and the environment stays locked until it finishes.
func TestAcquireNewestWinsAndLocks(t *testing.T) {
	s, _ := sweptStore(t)
	enqueue(t, s, "d1", envA, JobDeploy, 1)
	enqueue(t, s, "d2", envA, JobDeploy, 2)
	enqueue(t, s, "d3", envA, JobTeardown, 3)
	l := acquire(t, s)
	if l.JobID != 3 || l.Type != JobTeardown || l.Epoch != s.Epoch() {
		t.Fatalf("lease = %+v, want teardown job 3 at epoch %d", l, s.Epoch())
	}
	if got, want := statuses(t, s), []JobStatus{StatusSkipped, StatusSkipped, StatusInProgress}; !slices.Equal(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	enqueue(t, s, "d4", envA, JobDeploy, 4)
	if _, ok, err := s.Acquire(context.Background(), t0); ok || err != nil {
		t.Fatalf("locked environment leased again: ok=%v err=%v", ok, err)
	}
}

// Teardowns never fail; a deploy is requeued only while unclassified (GHES
// unavailable during AuthorizeDeploy), never once classified.
func TestLeaseTransitionRules(t *testing.T) {
	s, _ := sweptStore(t)
	enqueue(t, s, "d1", envA, JobTeardown, 1)
	td := acquire(t, s)
	if err := s.Finish(context.Background(), td, StatusFailed, t0); !errors.Is(err, ErrTeardownCannotFail) {
		t.Fatalf("teardown FAILED: %v", err)
	}
	if err := s.Finish(context.Background(), td, StatusQueued, t0); err == nil {
		t.Fatal("Finish accepted QUEUED")
	}
	if err := s.Requeue(context.Background(), td, t0.Add(time.Minute)); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	if _, ok, _ := s.Acquire(context.Background(), t0); ok {
		t.Fatal("requeued teardown leased before its backoff")
	}
	l, ok, err := s.Acquire(context.Background(), t0.Add(time.Minute))
	if err != nil || !ok || l.JobID != td.JobID {
		t.Fatalf("Acquire after backoff = %+v, %v, %v", l, ok, err)
	}
	finish(t, s, l, StatusSuccess)

	enqueue(t, s, "d2", envB, JobDeploy, 1)
	dl := acquire(t, s)
	if err := s.Requeue(context.Background(), dl, t0); err != nil {
		t.Fatalf("unclassified deploy requeue: %v", err)
	}
	dl = acquire(t, s)
	if dl.Attempts != 1 {
		t.Fatalf("requeued deploy lease = %+v, want 1 attempt", dl)
	}
	if err := s.Classify(context.Background(), dl, Classification{Trust: TrustTrusted}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if err := s.Requeue(context.Background(), dl, t0); !errors.Is(err, ErrDeployCannotRetry) {
		t.Fatalf("classified deploy requeue: %v", err)
	}
	jobs, err := s.Jobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if jobs[0].Attempts != 1 || jobs[0].Status != StatusSuccess {
		t.Fatalf("teardown job = %+v, want SUCCESS after 1 attempt", jobs[0])
	}
	if jobs[1].Status != StatusInProgress || jobs[1].Trust != TrustTrusted {
		t.Fatalf("deploy job = %+v, want IN_PROGRESS and trusted after the refused requeue", jobs[1])
	}
}

// Defense in depth: SQLite itself refuses a second IN_PROGRESS job for an
// environment, a FAILED teardown and a duplicate seq, whatever the Go code
// does.
func TestSchemaEnforcesLockAndTeardownRule(t *testing.T) {
	s, _ := sweptStore(t)
	enqueue(t, s, "d1", envA, JobTeardown, 1)
	enqueue(t, s, "d2", envA, JobDeploy, 2)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = 'IN_PROGRESS'`); err == nil {
		t.Error("two IN_PROGRESS jobs for one environment accepted")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = 'FAILED' WHERE type = 'teardown'`); err == nil {
		t.Error("FAILED teardown accepted")
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO jobs (preview_id, type, seq, status, created_at, repo, head_repo, pr_number,
		opener_login, opener_id, commit_sha, clone_url) SELECT preview_id, type, seq, status, created_at, repo, head_repo, pr_number,
		opener_login, opener_id, commit_sha, clone_url FROM jobs WHERE seq = 2`); err == nil {
		t.Error("duplicate (preview_id, seq) accepted")
	}
}

// crashAndSweep closes the store, reopens the file and sweeps it.
func crashAndSweep(t *testing.T, s *Store, path string, observed []Observation) (*Store, SweepResult) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s2.Close(); err != nil {
			t.Error(err)
		}
	})
	res, err := s2.StartupSweep(context.Background(), t0, observed)
	if err != nil {
		t.Fatalf("StartupSweep: %v", err)
	}
	return s2, res
}

func intact(env string, jobID int64) Observation {
	return Observation{EnvID: env, Running: true, NetworkBound: true, SecretsMounted: true, Routed: true, JobID: jobID}
}

// deployed returns a store where envA runs job 1 (SUCCESS).
func deployed(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	s, err := NewStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartupSweep(context.Background(), t0, nil); err != nil {
		t.Fatal(err)
	}
	enqueue(t, s, "d1", envA, JobDeploy, 1)
	finish(t, s, acquire(t, s), StatusSuccess)
	return s, path
}

// Daemon crash with an intact environment: kept, nothing re-armed.
func TestSweepKeepsIntactEnvironment(t *testing.T) {
	s, path := deployed(t)
	s, res := crashAndSweep(t, s, path, []Observation{intact(envA, 1)})
	if len(res.Destroy) != 0 {
		t.Fatalf("destroyed %v", res.Destroy)
	}
	if got := statuses(t, s); !slices.Equal(got, []JobStatus{StatusSuccess}) {
		t.Fatalf("statuses = %v", got)
	}
}

// D3: a reboot wiped the staged secrets. The environment is destroyed and
// its latest SUCCESS deploy re-armed, so it comes back.
func TestSweepRearmsAfterReboot(t *testing.T) {
	s, path := deployed(t)
	o := intact(envA, 1)
	o.SecretsMounted = false
	s, res := crashAndSweep(t, s, path, []Observation{o})
	if !slices.Equal(res.Destroy, []string{envA}) {
		t.Fatalf("destroy = %v, want [%s]", res.Destroy, envA)
	}
	if got := statuses(t, s); !slices.Equal(got, []JobStatus{StatusQueued}) {
		t.Fatalf("statuses = %v, want the deploy re-armed", got)
	}
	if l := acquire(t, s); l.JobID != 1 {
		t.Fatalf("re-armed deploy not leased: %+v", l)
	}
}

// A running environment whose route document is gone is not intact: it is
// destroyed and its deploy re-armed, so route and container come back
// together. Conversely, a lone route document is destroyed.
func TestSweepRouteMustMatchEnvironment(t *testing.T) {
	s, path := deployed(t)
	o := intact(envA, 1)
	o.Routed = false
	lone := Observation{EnvID: envB, Routed: true}
	s, res := crashAndSweep(t, s, path, []Observation{o, lone})
	if !slices.Equal(res.Destroy, []string{envA, envB}) {
		t.Fatalf("destroy = %v, want [%s %s]", res.Destroy, envA, envB)
	}
	if got := statuses(t, s); !slices.Equal(got, []JobStatus{StatusQueued}) {
		t.Fatalf("statuses = %v, want the deploy re-armed", got)
	}
}

// D3: the environment is intact but a newer deploy was leased when the
// daemon died. It no longer matches the latest intent (now FAILED): destroy.
func TestSweepDestroysEnvironmentSupersededByInterruptedDeploy(t *testing.T) {
	s, path := deployed(t)
	enqueue(t, s, "d2", envA, JobDeploy, 2)
	acquire(t, s)
	s, res := crashAndSweep(t, s, path, []Observation{intact(envA, 1)})
	if !slices.Equal(res.Destroy, []string{envA}) {
		t.Fatalf("destroy = %v, want [%s]", res.Destroy, envA)
	}
	if got := statuses(t, s); !slices.Equal(got, []JobStatus{StatusSuccess, StatusFailed}) {
		t.Fatalf("statuses = %v, want [SUCCESS FAILED]", got)
	}
}

// D2: an interrupted teardown is requeued, never failed; the environment it
// was removing is kept until the teardown runs again.
func TestSweepRequeuesInterruptedTeardown(t *testing.T) {
	s, path := deployed(t)
	enqueue(t, s, "d2", envA, JobTeardown, 2)
	stale := acquire(t, s)
	s, res := crashAndSweep(t, s, path, []Observation{intact(envA, 1)})
	if len(res.Destroy) != 0 {
		t.Fatalf("destroy = %v", res.Destroy)
	}
	if got := statuses(t, s); !slices.Equal(got, []JobStatus{StatusSuccess, StatusQueued}) {
		t.Fatalf("statuses = %v, want [SUCCESS QUEUED]", got)
	}
	// The dead worker's lease is refused; the new lease belongs to the new epoch.
	if err := s.Finish(context.Background(), stale, StatusSuccess, t0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale lease: %v, want ErrLeaseLost", err)
	}
	l := acquire(t, s)
	if l.JobID != 2 || l.Epoch != stale.Epoch+1 {
		t.Fatalf("lease = %+v", l)
	}
	if err := s.Requeue(context.Background(), stale, t0); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale lease requeue after reacquire: %v, want ErrLeaseLost", err)
	}
	finish(t, s, l, StatusSuccess)
}

// Leftovers no job tracks, or whose builder is not a live deploy, are
// destroyed; partial environments too.
func TestSweepDestroysUntrackedAndPartial(t *testing.T) {
	s, path := deployed(t)
	partial := Observation{EnvID: envB, NetworkBound: true, SecretsMounted: true, JobID: 99}
	stray := intact("pr-9-0909090909", 0)
	wrongEnv := intact("pr-8-0808080808", 1)
	_, res := crashAndSweep(t, s, path, []Observation{intact(envA, 1), partial, stray, wrongEnv})
	want := []string{envB, "pr-8-0808080808", "pr-9-0909090909"}
	if !slices.Equal(res.Destroy, want) {
		t.Fatalf("destroy = %v, want %v", res.Destroy, want)
	}
}

func TestSweepRejectsInvalidObservations(t *testing.T) {
	s, _ := sweptStore(t)
	before := s.Epoch()
	for name, obs := range map[string][]Observation{
		"empty env":    {{EnvID: ""}},
		"duplicate":    {intact(envA, 1), intact(envA, 2)},
		"negative job": {{EnvID: envA, JobID: -1}},
	} {
		if _, err := s.StartupSweep(context.Background(), t0, obs); !errors.Is(err, ErrInvalidObservation) {
			t.Errorf("%s: %v, want ErrInvalidObservation", name, err)
		}
	}
	if s.Epoch() != before {
		t.Fatal("a refused sweep changed the epoch")
	}
}

// Migrations: forward-only, a newer database is refused, a path the driver
// would truncate is refused.
func TestMigrations(t *testing.T) {
	ctx := context.Background()

	// Pre-versioning database: environments table at user_version 0.
	path := filepath.Join(t.TempDir(), "old.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// The DDL shipped before versioning, without any PRAGMA user_version.
	if _, err := db.ExecContext(ctx, `CREATE TABLE environments (
		id TEXT PRIMARY KEY,
		pr_number INTEGER NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO environments (id, pr_number, status) VALUES ('pr-1', 1, 'running')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, path)
	var version, tables int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("user_version = %d, %v; want %d", version, err, len(migrations))
	}
	// The queue supersedes the environment records: migration 2 drops them.
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name = 'environments'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("environments table still present (%d), %v", tables, err)
	}

	// Every migration sets exactly its own version.
	for i, m := range migrations {
		if !strings.Contains(m, fmt.Sprintf("PRAGMA user_version = %d;", i+1)) {
			t.Errorf("migration %d does not set user_version %d", i+1, i+1)
		}
	}

	// Newer than this binary.
	newer := filepath.Join(t.TempDir(), "newer.sqlite")
	db, err = sql.Open("sqlite", newer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := NewStore(ctx, newer); err == nil {
		_ = s.Close()
		t.Fatal("NewStore opened a database newer than the binary")
	}

	for _, bad := range []string{"", "/var/lib/previewd/x.sqlite?_pragma=journal_mode(DELETE)", "/tmp/a#b"} {
		if s, err := NewStore(ctx, bad); err == nil {
			_ = s.Close()
			t.Errorf("NewStore accepted path %q", bad)
		}
	}
}

// The connection carries the documented pragmas.
func TestConnectionPragmas(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	for pragma, want := range map[string]string{
		"journal_mode": "wal",
		"synchronous":  "2", // FULL
		"busy_timeout": "5000",
		"foreign_keys": "1",
	} {
		var got string
		if err := s.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", pragma, err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %s, want %s", pragma, got, want)
		}
	}
}
