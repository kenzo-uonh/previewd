package store

// The V1 state machine (jobs_spbt_v1_test.go) driving the real Store: task
// A2 of docs/specs/V1-previewd.md. Run it alone with
//
//	CGO_ENABLED=0 go test -run TestV1Store_StateMachine ./internal/store
//
// This file pinned the store API that tasks B1 (schema version 3), D3
// (approval gating, store side), F (pruning) and G (expiry, store side)
// implement, refining V1 spec section 3.4 where it was silent. It was
// behind the build tag v1spbt until the store passed it (B1).
//
// The pinned API, in addition to the MVP queue:
//
//	StatusPendingApproval JobStatus = "PENDING_APPROVAL"
//	type Origin string   // OriginWebhook, OriginApproval, OriginRevocation, OriginRevalidation, OriginTTL
//	type Trust string    // TrustUnclassified, TrustTrusted, TrustUntrusted
//	type RevocationReason string // RevokedDismissed, RevokedPermissionLost, ... (schema 3 vocabulary)
//	Job:      + Origin, Trust, CreatedAt, FinishedAt (Unix ms; 0 while not terminal)
//	Source:   + HeadRepo, OpenerLogin, OpenerID
//	Delivery: + ReceivedAt (deliveries.received_at, jobs.created_at)
//
//	Enqueue(ctx, Delivery) (Verdict, int64, error)
//	    stale against max(jobs.seq, watermarks.seq); an accepted deploy
//	    revokes, at its seq, every approval of another commit (new_head).
//	Approve(ctx, Grant, now, AuditEvent) (jobID int64, error)
//	    records the grant; when !Trusted and the grant is live, unparks the
//	    latest job if it is the parked deploy of the commit, or else, when
//	    OpenHead and the latest job does not already deploy the commit,
//	    queues a deploy (origin approval). Returns the job, or 0.
//	Revoke(ctx, Revoke, now, AuditEvent) (teardownJobID int64, error)
//	    records the revocation; when !Trusted, no grant of the commit stays
//	    live and the latest job deploys the commit (QUEUED, IN_PROGRESS,
//	    PENDING_APPROVAL or SUCCESS), queues a teardown (origin revocation)
//	    of that commit (A2-1). Returns the job, or 0.
//	Classify(ctx, Lease, Trust) error
//	    trusted, or untrusted only with a live approval of the lease's
//	    commit in the same transaction (ErrNotApproved otherwise, nothing
//	    changed). Writes its audit row.
//	Park(ctx, Lease) error            IN_PROGRESS -> PENDING_APPROVAL
//	Requeue(ctx, Lease, notBefore) error
//	    a teardown, or a deploy not yet classified (GHES unavailable):
//	    QUEUED, attempts + 1. A classified deploy: ErrDeployCannotRetry.
//	Finish(ctx, Lease, JobStatus, now) error     sets finished_at
//	EnqueueInternal(ctx, envID, Origin, RevocationReason, now, AuditEvent) (int64, error)
//	    a teardown of the latest job's commit (origin revalidation or
//	    ttl). With a reason, a live approval of that commit is revoked at
//	    now's UUIDv1 ticks in the same transaction.
//	ApprovalLive(ctx, envID, commitSHA) (bool, error)
//	    a grant newer than every revocation of (env, commit), by seq.
//	Expired(ctx, ttl, now) ([]string, error)
//	    sorted environments whose latest job is a SUCCESS deploy finished
//	    at or before now - ttl.
//	Prune(ctx, PruneRequest) (PruneStats, error)
//	    terminal jobs finished before Now - Retention that are neither the
//	    latest of their environment nor in Builders, after raising the
//	    watermark; deliveries received before
//	    Now - max(Retention, DeliveryMaxAge + 5 min); in batches of Batch.
//	VerifyAudit(ctx) error
//
// Every internal job takes seq = MaxSeq(env) + 1 (A2-2), never a seq derived
// from now.

import (
	"context"
	"errors"
	"flag"
	"maps"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// v1Repo is the base repository of every environment; an untrusted one's
// head lives in a fork.
const (
	v1Repo     = "acme/app"
	v1ForkRepo = "outside/app"
	v1CloneURL = "https://git.example.internal/acme/app.git"
)

type v1StoreBackend struct {
	ctx   context.Context
	dir   string
	path  string
	store *Store
	cfg   v1Config

	leases map[int64]Lease // held by a live worker, by job ID
	stale  []Lease         // held by workers a crash killed
}

func newV1StoreBackend(t *rapid.T, base string) *v1StoreBackend {
	dir, err := os.MkdirTemp(base, "spbt-v1-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	return &v1StoreBackend{ctx: context.Background(), dir: dir, path: dir + "/previewd.sqlite", leases: map[int64]Lease{}}
}

func (b *v1StoreBackend) must(t *rapid.T, err error, what string) {
	t.Helper()
	if isBusy(err) {
		t.Fatalf("%s: SQLITE_BUSY surfaced: %v", what, err)
	}
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func (b *v1StoreBackend) configure(cfg v1Config) { b.cfg = cfg }

// source is what GHES reports for the PR of envID at commit: everything
// but the commit is fixed per environment.
func (b *v1StoreBackend) source(envID, commit string) Source {
	head := v1Repo
	if b.cfg.untrusted[envID] {
		head = v1ForkRepo
	}
	return Source{
		Repo: v1Repo, HeadRepo: head, PRNumber: int64(slices.Index(v1Envs, envID) + 1),
		OpenerLogin: "opener", OpenerID: 4242, CommitSHA: commit, CloneURL: v1CloneURL,
	}
}

func (b *v1StoreBackend) audit(kind AuditKind, envID, commit, detail string) AuditEvent {
	src := b.source(envID, commit)
	return AuditEvent{Kind: kind, EnvID: envID, Repo: src.Repo, PRNumber: src.PRNumber, CommitSHA: commit,
		ActorLogin: "approver", ActorID: 7, Detail: detail}
}

func (b *v1StoreBackend) crash(t *rapid.T) {
	b.must(t, b.store.Close(), "close store")
	b.store = nil
	for _, id := range slices.Sorted(maps.Keys(b.leases)) {
		b.stale = append(b.stale, b.leases[id])
	}
	b.leases = map[int64]Lease{}
}

func (b *v1StoreBackend) boot(t *rapid.T, now time.Time, observed []Observation) SweepResult {
	if b.store == nil {
		s, err := NewStore(b.ctx, b.path)
		b.must(t, err, "open store")
		b.store = s
		if _, _, err := s.Acquire(b.ctx, now); !errors.Is(err, ErrNotSwept) {
			t.Fatalf("acquire before the sweep: got %v, want ErrNotSwept", err)
		}
	}
	res, err := b.store.StartupSweep(b.ctx, now, observed)
	b.must(t, err, "startup sweep")
	// A lease from before the crash is refused everywhere, and changes
	// nothing (verify runs after the command).
	for _, l := range b.stale {
		if err := b.store.Finish(b.ctx, l, StatusSuccess, now); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("finish with stale lease %+v: got %v, want ErrLeaseLost", l, err)
		}
		switch l.Type {
		case JobTeardown:
			if err := b.store.Requeue(b.ctx, l, now); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("requeue with stale lease %+v: got %v, want ErrLeaseLost", l, err)
			}
		case JobDeploy:
			if err := b.store.Classify(b.ctx, l, TrustTrusted); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("classify with stale lease %+v: got %v, want ErrLeaseLost", l, err)
			}
			if err := b.store.Park(b.ctx, l); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("park with stale lease %+v: got %v, want ErrLeaseLost", l, err)
			}
		}
	}
	b.stale = nil
	return res
}

func (b *v1StoreBackend) enqueue(t *rapid.T, d v1Emission, now time.Time) (Verdict, int64) {
	typ := JobDeploy
	if d.Kind == v1KindTeardown {
		typ = JobTeardown
	}
	verdict, id, err := b.store.Enqueue(b.ctx, Delivery{
		ID: d.ID, PayloadSHA256: d.Payload, EnvID: d.EnvID, Type: typ, Seq: d.Seq,
		Source: b.source(d.EnvID, d.Commit), ReceivedAt: now,
	})
	b.must(t, err, "enqueue")
	return verdict, id
}

func (b *v1StoreBackend) approve(t *rapid.T, g v1Grant, now time.Time) int64 {
	id, err := b.store.Approve(b.ctx, Grant{
		EnvID: g.EnvID, Source: b.source(g.EnvID, g.Commit), Seq: g.Seq,
		ApproverLogin: "approver", ApproverID: 7, Via: ApprovalViaReview, ReviewID: 99,
		Trusted: g.Trusted, OpenHead: g.OpenHead,
	}, now, b.audit(AuditApprovalGranted, g.EnvID, g.Commit, "review"))
	b.must(t, err, "approve")
	return id
}

func (b *v1StoreBackend) revoke(t *rapid.T, r v1Revocation, now time.Time) int64 {
	src := b.source(r.EnvID, r.Commit)
	id, err := b.store.Revoke(b.ctx, Revoke{
		EnvID: r.EnvID, Repo: src.Repo, PRNumber: src.PRNumber, CommitSHA: r.Commit, Seq: r.Seq,
		Reason: RevokedDismissed, Trusted: r.Trusted,
	}, now, b.audit(AuditApprovalRevoked, r.EnvID, r.Commit, string(RevokedDismissed)))
	b.must(t, err, "revoke")
	return id
}

func (b *v1StoreBackend) acquire(t *rapid.T, now time.Time) (v1Lease, bool) {
	l, ok, err := b.store.Acquire(b.ctx, now)
	b.must(t, err, "acquire")
	if !ok {
		return v1Lease{}, false
	}
	if want := b.source(l.EnvID, l.Source.CommitSHA); l.Source != want {
		t.Fatalf("lease %d source %+v, want %+v", l.JobID, l.Source, want)
	}
	b.leases[l.JobID] = l
	return v1Lease{JobID: l.JobID, EnvID: l.EnvID, Type: l.Type, Seq: l.Seq, Epoch: l.Epoch, Attempts: l.Attempts, Commit: l.Source.CommitSHA}, true
}

func (b *v1StoreBackend) lease(t *rapid.T, jobID int64) Lease {
	l, ok := b.leases[jobID]
	if !ok {
		t.Fatalf("no lease held on job %d", jobID)
	}
	return l
}

func (b *v1StoreBackend) classify(t *rapid.T, jobID int64, trust v1Trust) bool {
	err := b.store.Classify(b.ctx, b.lease(t, jobID), Trust(trust))
	if errors.Is(err, ErrNotApproved) {
		return true
	}
	b.must(t, err, "classify")
	return false
}

func (b *v1StoreBackend) park(t *rapid.T, jobID int64) {
	b.must(t, b.store.Park(b.ctx, b.lease(t, jobID)), "park")
	delete(b.leases, jobID)
}

func (b *v1StoreBackend) requeue(t *rapid.T, jobID int64, notBefore time.Time) bool {
	err := b.store.Requeue(b.ctx, b.lease(t, jobID), notBefore)
	if errors.Is(err, ErrDeployCannotRetry) {
		return true
	}
	b.must(t, err, "requeue")
	delete(b.leases, jobID)
	return false
}

func (b *v1StoreBackend) finish(t *rapid.T, jobID int64, status JobStatus, now time.Time) bool {
	err := b.store.Finish(b.ctx, b.lease(t, jobID), status, now)
	if errors.Is(err, ErrTeardownCannotFail) {
		return true
	}
	b.must(t, err, "finish")
	delete(b.leases, jobID)
	return false
}

func (b *v1StoreBackend) enqueueInternal(t *rapid.T, envID string, origin v1Origin, revoke bool, now time.Time) int64 {
	var reason RevocationReason
	kind := AuditTeardown
	if revoke {
		reason = RevokedPermissionLost
	}
	if origin == v1OriginTTL {
		kind = AuditTTLExpired
	}
	id, err := b.store.EnqueueInternal(b.ctx, envID, Origin(origin), reason, now, b.audit(kind, envID, "", string(origin)))
	b.must(t, err, "enqueue internal")
	return id
}

func (b *v1StoreBackend) approvalLive(t *rapid.T, envID, commit string) bool {
	live, err := b.store.ApprovalLive(b.ctx, envID, commit)
	b.must(t, err, "approval live")
	return live
}

func (b *v1StoreBackend) prune(t *rapid.T, req v1PruneRequest) (int64, int64) {
	stats, err := b.store.Prune(b.ctx, PruneRequest(req))
	b.must(t, err, "prune")
	if stats.Boots != 0 {
		t.Fatalf("prune deleted %d boots with fewer than 100 recorded", stats.Boots)
	}
	return stats.Jobs, stats.Deliveries
}

// verify compares every table with the model, asks SQLite for the lock
// integrity, and checks the audit chain.
func (b *v1StoreBackend) verify(t *rapid.T, x *v1Machine) {
	m := &x.m
	jobs, err := b.store.Jobs(b.ctx)
	b.must(t, err, "list jobs")
	got := make([]v1Job, 0, len(jobs))
	for _, j := range jobs {
		if want := b.source(j.EnvID, j.Source.CommitSHA); j.Source != want {
			t.Fatalf("job %d source %+v, want %+v", j.ID, j.Source, want)
		}
		got = append(got, v1Job{
			ID: j.ID, EnvID: j.EnvID, Type: j.Type, Origin: v1Origin(j.Origin), Seq: j.Seq, Status: j.Status,
			Trust: v1Trust(j.Trust), Attempts: j.Attempts, NotBefore: j.NotBefore, LeaseEpoch: j.LeaseEpoch,
			CreatedAt: j.CreatedAt, FinishedAt: j.FinishedAt, Commit: j.Source.CommitSHA,
		})
	}
	if want := m.sortedJobs(); !slices.Equal(got, want) {
		t.Fatalf("jobs table diverged from the model\n db:    %+v\n model: %+v", got, want)
	}

	rows, err := b.store.db.QueryContext(b.ctx, `SELECT delivery_id, preview_id, seq, verdict, payload_sha256, received_at FROM deliveries`)
	b.must(t, err, "list deliveries")
	deliveries := map[string]v1DeliveryRecord{}
	for rows.Next() {
		var id string
		var r v1DeliveryRecord
		var verdict string
		b.must(t, rows.Scan(&id, &r.EnvID, &r.Seq, &verdict, &r.Payload, &r.ReceivedAt), "scan delivery")
		r.Verdict = Verdict(verdict)
		deliveries[id] = r
	}
	b.must(t, rows.Err(), "list deliveries")
	b.must(t, rows.Close(), "close deliveries")
	if !maps.Equal(deliveries, m.deliveries) {
		t.Fatalf("deliveries diverged from the model\n db:    %+v\n model: %+v", deliveries, m.deliveries)
	}

	for _, e := range x.envs {
		var maxSeq int64
		b.must(t, b.store.db.QueryRowContext(b.ctx, `
			SELECT coalesce(max(seq), 0) FROM (
				SELECT seq FROM jobs WHERE preview_id = ?
				UNION ALL SELECT seq FROM watermarks WHERE preview_id = ?)`, e, e).Scan(&maxSeq), "max seq")
		if maxSeq != m.maxSeq(e) {
			t.Fatalf("MaxSeq(%s) = %d in the store, %d in the model", e, maxSeq, m.maxSeq(e))
		}
		for _, c := range v1Commits {
			if got, want := b.approvalLive(t, e, c), liveSpec(m.approvals, e, c); got != want {
				t.Fatalf("approval of %s at %s live = %v in the store, %v in the model", e, short(c), got, want)
			}
		}
	}

	if x.cfg.ttl > 0 {
		expired, err := b.store.Expired(b.ctx, time.Duration(x.cfg.ttl)*v1Tick, x.now())
		b.must(t, err, "expired")
		if want := x.expirableEnvs(); !slices.Equal(expired, want) {
			t.Fatalf("expired = %v in the store, %v in the model", expired, want)
		}
	}

	var maxInProgress int
	b.must(t, b.store.db.QueryRowContext(b.ctx,
		`SELECT coalesce(max(n), 0) FROM (SELECT count(*) AS n FROM jobs WHERE status = 'IN_PROGRESS' GROUP BY preview_id)`).Scan(&maxInProgress),
		"lock integrity query")
	if maxInProgress > 1 {
		t.Fatalf("SafetyOneJobPerEnv: %d IN_PROGRESS jobs for one environment in the store", maxInProgress)
	}
	b.must(t, b.store.VerifyAudit(b.ctx), "verify audit chain")
}

func (b *v1StoreBackend) close(t *rapid.T) {
	if b.store != nil {
		if err := b.store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	}
	if err := os.RemoveAll(b.dir); err != nil {
		t.Errorf("remove temp dir: %v", err)
	}
}

// v1StoreMaxChecks caps the runs of the store-backed machine. Each run opens
// and fsyncs a real SQLite file at every transaction, about a hundred times
// the cost of a model-only run: make verify's 10,000 checks go to the
// reference model and its mutants, the store gets at most this many.
const v1StoreMaxChecks = 500

// TestV1Store_StateMachine drives the real Store, on a real SQLite file
// (modernc, WAL), in lockstep with the reference model: every table equals
// the model after every command, and every property of the model holds.
func TestV1Store_StateMachine(t *testing.T) {
	checks := flag.Lookup("rapid.checks")
	if checks == nil {
		t.Fatal("flag rapid.checks is not registered")
	}
	if n, err := strconv.Atoi(checks.Value.String()); err != nil {
		t.Fatalf("rapid.checks: %v", err)
	} else if n > v1StoreMaxChecks {
		setTestFlag(t, "rapid.checks", strconv.Itoa(v1StoreMaxChecks))
	}
	base := t.TempDir()
	rapid.Check(t, func(t *rapid.T) {
		runV1(t, v1Faithful, newV1StoreBackend(t, base))
	})
}
