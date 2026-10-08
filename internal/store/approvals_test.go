package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	commitA = strings.Repeat("a", 40)
	commitB = strings.Repeat("b", 40)
)

func sourceAt(commit string) Source {
	src := testSource
	src.CommitSHA = commit
	return src
}

func testAuditEvent(kind AuditKind, detail string) AuditEvent {
	return AuditEvent{Kind: kind, EnvID: envA, Repo: testSource.Repo, PRNumber: testSource.PRNumber, Detail: detail}
}

// grantOf is an approval of commit delivered at seq; its delivery ID and
// body are distinct per (commit, seq).
func grantOf(commit string, seq int64) Grant {
	id := fmt.Sprintf("grant-%s-%d", commit[:4], seq)
	return Grant{DeliveryID: id, PayloadSHA256: payloadHash("body of " + id), EnvID: envA, Source: sourceAt(commit), Seq: seq,
		ApproverLogin: "approver", ApproverID: 7, Via: ApprovalViaReview, ReviewID: 99, OpenHead: true}
}

func grantAudit(g Grant) AuditEvent {
	ev := testAuditEvent(AuditApprovalGranted, string(g.Via))
	ev.EnvID, ev.CommitSHA, ev.ActorLogin, ev.ActorID = g.EnvID, g.Source.CommitSHA, g.ApproverLogin, g.ApproverID
	return ev
}

func approve(t *testing.T, s *Store, g Grant) int64 {
	t.Helper()
	v, id, err := s.Approve(context.Background(), g, t0, grantAudit(g))
	if err != nil || v != VerdictAccepted {
		t.Fatalf("Approve %+v = %s, %v", g, v, err)
	}
	return id
}

func revocationOf(commit string, seq int64) Revoke {
	id := fmt.Sprintf("revoke-%s-%d", commit[:4], seq)
	return Revoke{DeliveryID: id, PayloadSHA256: payloadHash("body of " + id), EnvID: envA, Repo: testSource.Repo,
		PRNumber: testSource.PRNumber, CommitSHA: commit, Seq: seq, Reason: RevokedDismissed}
}

func revocationAudit(r Revoke) AuditEvent {
	ev := testAuditEvent(AuditApprovalRevoked, string(r.Reason))
	ev.CommitSHA = r.CommitSHA
	return ev
}

func revoke(t *testing.T, s *Store, commit string, seq int64) int64 {
	t.Helper()
	r := revocationOf(commit, seq)
	v, id, err := s.Revoke(context.Background(), r, t0, revocationAudit(r))
	if err != nil || v != VerdictAccepted {
		t.Fatalf("Revoke %s at %d = %s, %v", commit, seq, v, err)
	}
	return id
}

func live(t *testing.T, s *Store, commit string) bool {
	t.Helper()
	ok, err := s.ApprovalLive(context.Background(), envA, commit)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func enqueueAt(t *testing.T, s *Store, id string, typ JobType, seq int64, commit string) int64 {
	t.Helper()
	d := testDelivery(id, envA, typ, seq)
	d.Source = sourceAt(commit)
	v, jobID, err := s.Enqueue(context.Background(), d)
	if err != nil || v != VerdictAccepted {
		t.Fatalf("Enqueue %s = %s, %v", id, v, err)
	}
	return jobID
}

func auditKinds(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT kind || '/' || detail FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	return out
}

// A revocation recorded before its grant (a dismissal delivered first) keeps
// the older grant dead whenever it arrives; only a newer grant is live
// (V1-model.md A2-5).
func TestRevocationBeforeGrant(t *testing.T) {
	s, _ := sweptStore(t)
	revoke(t, s, commitA, 20)
	if approve(t, s, grantOf(commitA, 10)); live(t, s, commitA) {
		t.Fatal("a grant older than a recorded revocation is live")
	}
	if approve(t, s, grantOf(commitA, 30)); !live(t, s, commitA) {
		t.Fatal("a grant newer than every revocation is not live")
	}
	// A revocation delivered after a newer grant does not cancel it.
	if revoke(t, s, commitA, 25); !live(t, s, commitA) {
		t.Fatal("an older revocation cancelled a newer grant")
	}
	if revoke(t, s, commitA, 30); live(t, s, commitA) {
		t.Fatal("a revocation at the grant's seq left it live")
	}
}

// A push revokes every other commit at its seq, including a commit whose
// grant is still in flight; the head itself stays approvable.
func TestNewHeadRevokesEveryOtherCommit(t *testing.T) {
	s, _ := sweptStore(t)
	g := grantOf(commitA, 10)
	g.Trusted = true // record only: no job effect
	approve(t, s, g)
	enqueueAt(t, s, "push-b", JobDeploy, 20, commitB)
	if live(t, s, commitA) {
		t.Fatal("approval of the previous head survived the push")
	}
	if got := auditKinds(t, s); !slices.Equal(got, []string{"approval_granted/review", "approval_revoked/new_head"}) {
		t.Fatalf("audit = %v, want the grant and its new_head revocation", got)
	}
	g = grantOf(commitB, 15)
	g.Trusted = true
	if approve(t, s, g); !live(t, s, commitB) {
		t.Fatal("approval of the head is not live")
	}
	// A late grant of a commit never seen before the push is dead too.
	late := strings.Repeat("c", 40)
	g = grantOf(late, 12)
	g.Trusted = true
	if approve(t, s, g); live(t, s, late) {
		t.Fatal("a late grant of an unseen commit, older than the push, is live")
	}
	// Pushing A back revokes B at the new seq, and A at the push of B.
	enqueueAt(t, s, "push-a", JobDeploy, 40, commitA)
	g = grantOf(commitA, 25)
	g.Trusted = true
	if approve(t, s, g); !live(t, s, commitA) || live(t, s, commitB) {
		t.Fatalf("after pushing A back: A live %v, B live %v; want true, false", live(t, s, commitA), live(t, s, commitB))
	}
}

// Fail closed: Classify(untrusted) refuses without a live approval of the
// lease's commit, read in the same transaction, and changes nothing; with
// one, it records the approver as the audit actor.
func TestClassifyUntrustedFailsClosed(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueueAt(t, s, "d1", JobDeploy, 10, commitA)
	l := acquire(t, s)
	revoke(t, s, commitA, 5)
	approve(t, s, grantOf(commitB, 11)) // another commit
	before := auditKinds(t, s)
	if err := s.Classify(ctx, l, TrustUntrusted); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("Classify without approval: %v, want ErrNotApproved", err)
	}
	if jobs, err := s.Jobs(ctx); err != nil || jobs[0].Trust != TrustUnclassified {
		t.Fatalf("refused Classify changed the job: %+v, %v", jobs, err)
	}
	if got := auditKinds(t, s); !slices.Equal(got, before) {
		t.Fatalf("refused Classify wrote audit %v", got[len(before):])
	}
	approve(t, s, grantOf(commitA, 12))
	if err := s.Classify(ctx, l, TrustUntrusted); err != nil {
		t.Fatalf("Classify with a live approval: %v", err)
	}
	if err := s.Classify(ctx, l, TrustTrusted); !errors.Is(err, ErrAlreadyClassified) {
		t.Fatalf("second Classify: %v, want ErrAlreadyClassified", err)
	}
	var actor string
	var actorID int64
	if err := s.db.QueryRowContext(ctx, `SELECT actor_login, actor_id FROM audit_events WHERE kind = 'untrusted_deploy'`).Scan(&actor, &actorID); err != nil {
		t.Fatal(err)
	}
	if actor != "approver" || actorID != 7 {
		t.Fatalf("untrusted_deploy actor = %s#%d, want approver#7", actor, actorID)
	}
	if err := s.Park(ctx, l); !errors.Is(err, ErrAlreadyClassified) {
		t.Fatalf("Park of a classified deploy: %v, want ErrAlreadyClassified", err)
	}
}

// A grant judges the latest job: it unparks the parked deploy of its exact
// commit, and nothing else.
func TestApproveUnparksExactCommitOnly(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	id := enqueueAt(t, s, "d1", JobDeploy, 10, commitA)
	l := acquire(t, s)
	if err := s.Park(ctx, l); err != nil {
		t.Fatal(err)
	}
	g := grantOf(commitB, 11)
	g.OpenHead = false
	if got := approve(t, s, g); got != 0 {
		t.Fatalf("grant of another commit = job %d, want 0", got)
	}
	if got := approve(t, s, grantOf(commitA, 12)); got != id {
		t.Fatalf("grant of the parked commit = job %d, want %d", got, id)
	}
	if jobs, err := s.Jobs(ctx); err != nil || jobs[0].Status != StatusQueued || len(jobs) != 1 {
		t.Fatalf("jobs = %+v, %v; want the parked deploy QUEUED", jobs, err)
	}
}

// A revocation queues a teardown only above a latest intent that deploys
// the revoked commit (A2-1).
func TestRevokeTeardownOnlyAboveHeadIntent(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueueAt(t, s, "d1", JobDeploy, 10, commitA)
	approve(t, s, grantOf(commitA, 11))
	enqueueAt(t, s, "d2", JobDeploy, 20, commitB)
	if got := revoke(t, s, commitA, 21); got != 0 {
		t.Fatalf("revocation of A behind a deploy of B queued teardown %d", got)
	}
	approve(t, s, grantOf(commitB, 22))
	teardown := revoke(t, s, commitB, 23)
	jobs, err := s.Jobs(ctx)
	if err != nil || teardown == 0 || len(jobs) != 3 {
		t.Fatalf("revocation of the head = job %d, jobs %+v, %v", teardown, jobs, err)
	}
	if j := jobs[2]; j.Type != JobTeardown || j.Origin != OriginRevocation || j.Seq != 21 || j.Source.CommitSHA != commitB {
		t.Fatalf("revocation teardown = %+v, want origin revocation at MaxSeq + 1 for B", j)
	}
}

// Fail closed: an audit event that does not describe the operation is
// refused, and nothing is recorded.
func TestOperationsRefuseMismatchedAudit(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	g := grantOf(commitA, 10)
	for name, ev := range map[string]AuditEvent{
		"other kind":   testAuditEvent(AuditApprovalRevoked, "dismissed"),
		"other commit": {Kind: AuditApprovalGranted, EnvID: envA, Repo: testSource.Repo, PRNumber: testSource.PRNumber, CommitSHA: commitB, ActorLogin: "approver", ActorID: 7, Detail: "review"},
		"other actor":  {Kind: AuditApprovalGranted, EnvID: envA, Repo: testSource.Repo, PRNumber: testSource.PRNumber, CommitSHA: commitA, ActorLogin: "mallory", ActorID: 8, Detail: "review"},
		"other via":    {Kind: AuditApprovalGranted, EnvID: envA, Repo: testSource.Repo, PRNumber: testSource.PRNumber, CommitSHA: commitA, ActorLogin: "approver", ActorID: 7, Detail: "label"},
	} {
		if _, _, err := s.Approve(ctx, g, t0, ev); !errors.Is(err, ErrInvalidAudit) {
			t.Errorf("%s: %v, want ErrInvalidAudit", name, err)
		}
	}
	if live(t, s, commitA) || len(auditKinds(t, s)) != 0 {
		t.Fatal("a refused Approve recorded something")
	}
}

// EnqueueInternal with a reason revokes the live approval of what runs at
// now's ticks; a grant sent before now stays dead, one sent after is live.
func TestEnqueueInternalRevokesAtNow(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueueAt(t, s, "d1", JobDeploy, seqAt(t0.Add(-time.Hour)), commitA)
	approve(t, s, grantOf(commitA, seqAt(t0.Add(-time.Minute))))
	ev := testAuditEvent(AuditTeardown, string(OriginRevalidation))
	id, err := s.EnqueueInternal(ctx, envA, OriginRevalidation, RevokedPermissionLost, t0, ev)
	if err != nil || id == 0 {
		t.Fatalf("EnqueueInternal = %d, %v", id, err)
	}
	if live(t, s, commitA) {
		t.Fatal("the approval of what runs is still live after the re-validation revoked it")
	}
	if approve(t, s, grantOf(commitA, seqAt(t0.Add(-time.Second)))); live(t, s, commitA) {
		t.Fatal("a grant sent before the re-validation is live")
	}
	if approve(t, s, grantOf(commitA, seqAt(t0.Add(time.Second)))); !live(t, s, commitA) {
		t.Fatal("a grant sent after the re-validation is not live")
	}
	if got := auditKinds(t, s); !slices.Contains(got, "approval_revoked/permission_lost") || !slices.Contains(got, "teardown/revalidation") {
		t.Fatalf("audit = %v", got)
	}
	var commit string
	if err := s.db.QueryRowContext(ctx, `SELECT commit_sha FROM audit_events WHERE kind = 'teardown'`).Scan(&commit); err != nil || commit != commitA {
		t.Fatalf("teardown audit commit = %q (%v), want the teardown's commit", commit, err)
	}
	for name, call := range map[string]func() error{
		"ttl with a reason": func() error {
			_, err := s.EnqueueInternal(ctx, envA, OriginTTL, RevokedPermissionLost, t0, testAuditEvent(AuditTTLExpired, "ttl"))
			return err
		},
		"approval origin": func() error {
			_, err := s.EnqueueInternal(ctx, envA, OriginApproval, "", t0, testAuditEvent(AuditTeardown, "revalidation"))
			return err
		},
		"new_head reason": func() error {
			_, err := s.EnqueueInternal(ctx, envA, OriginRevalidation, RevokedNewHead, t0, testAuditEvent(AuditTeardown, "revalidation"))
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrInvalidInternalJob) {
			t.Errorf("%s: %v, want ErrInvalidInternalJob", name, err)
		}
	}
	if _, err := s.EnqueueInternal(ctx, envB, OriginTTL, "", t0, testAuditEvent(AuditTTLExpired, "ttl")); !errors.Is(err, ErrNoJob) {
		t.Errorf("internal teardown of an environment without jobs: %v, want ErrNoJob", err)
	}
}

// D2: an approval or a revocation delivery is a replay when its ID or its
// signed body was already recorded. A captured approval resent under a
// fresh, later delivery ID after a dismissal does not revive the approval,
// writes no audit row and queues nothing.
func TestApproveAndRevokeReplay(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueueAt(t, s, "d1", JobDeploy, 10, commitA)
	g := grantOf(commitA, 11)
	approve(t, s, g)
	revoke(t, s, commitA, 12) // queues the revocation teardown
	before := auditKinds(t, s)
	jobsBefore, err := s.Jobs(ctx)
	if err != nil {
		t.Fatal(err)
	}

	forged := g
	forged.DeliveryID, forged.Seq = "forged-grant", 13 // same body, fresh ID and time
	for name, replay := range map[string]Grant{"same delivery": g, "same body, fresh ID": forged} {
		v, id, err := s.Approve(ctx, replay, t0, grantAudit(replay))
		if err != nil || v != VerdictReplay || id != 0 {
			t.Fatalf("%s = %s/%d, %v; want replay", name, v, id, err)
		}
	}
	if live(t, s, commitA) {
		t.Fatal("a replayed approval revived a dismissed one")
	}
	r := revocationOf(commitA, 12)
	r.DeliveryID = "forged-revocation"
	if v, _, err := s.Revoke(ctx, r, t0, revocationAudit(r)); err != nil || v != VerdictReplay {
		t.Fatalf("replayed revocation = %s, %v; want replay", v, err)
	}
	if got := auditKinds(t, s); !slices.Equal(got, before) {
		t.Fatalf("replays wrote audit rows %v", got[len(before):])
	}
	if jobs, err := s.Jobs(ctx); err != nil || !slices.Equal(jobs, jobsBefore) {
		t.Fatalf("replays changed the jobs: %+v, %v", jobs, err)
	}
	// A grant body replayed as a deploy delivery is a replay too: one key space.
	d := testDelivery("forged-deploy", envA, JobDeploy, 14)
	d.PayloadSHA256 = g.PayloadSHA256
	if v, _, err := s.Enqueue(ctx, d); err != nil || v != VerdictReplay {
		t.Fatalf("approval body as a deploy = %s, %v; want replay", v, err)
	}
}

// The chain detects a row changed or deleted behind the triggers.
func TestVerifyAuditDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]string{
		"changed actor":  `UPDATE audit_events SET actor_login = 'mallory', actor_id = 8 WHERE id = 2`,
		"changed detail": `UPDATE audit_events SET detail = 'label' WHERE id = 2`,
		"deleted row":    `DELETE FROM audit_events WHERE id = 2`,
		"relinked row":   `UPDATE audit_events SET prev_hash = (SELECT hash FROM audit_events WHERE id = 1) WHERE id = 3`,
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := sweptStore(t)
			ctx := context.Background()
			approve(t, s, grantOf(commitA, 10))
			approve(t, s, grantOf(commitA, 11))
			approve(t, s, grantOf(commitA, 12))
			if err := s.VerifyAudit(ctx); err != nil {
				t.Fatalf("untouched chain: %v", err)
			}
			if _, err := s.db.ExecContext(ctx, `DROP TRIGGER audit_events_no_update; DROP TRIGGER audit_events_no_delete;`+tamper); err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyAudit(ctx); !errors.Is(err, ErrAuditChain) {
				t.Fatalf("tampered chain: %v, want ErrAuditChain", err)
			}
		})
	}
}

// A row rewritten with a hash recomputed over its own content passes its own
// check; the next row's link to it fails.
func TestVerifyAuditDetectsForgedRow(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	approve(t, s, grantOf(commitA, 10))
	approve(t, s, grantOf(commitA, 11))
	approve(t, s, grantOf(commitA, 12))
	var prev string
	if err := s.db.QueryRowContext(ctx, `SELECT hash FROM audit_events WHERE id = 1`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	forged := auditRow{ID: 2, At: t0.UnixMilli(), PrevHash: prev, Event: AuditEvent{Kind: AuditApprovalGranted, EnvID: envA,
		Repo: testSource.Repo, PRNumber: testSource.PRNumber, CommitSHA: commitA, ActorLogin: "mallory", ActorID: 8, Detail: "review"}}
	forged.Hash = chainHash(prev, forged)
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER audit_events_no_update;
		UPDATE audit_events SET actor_login = 'mallory', actor_id = 8, hash = ? WHERE id = 2`, forged.Hash); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAudit(ctx); !errors.Is(err, ErrAuditChain) || !strings.Contains(err.Error(), "row 3 does not follow row 2") {
		t.Fatalf("forged row: %v, want ErrAuditChain at the link of row 3", err)
	}
}

// F1: pruning keeps verdicts. After pruning, an old redelivery is stale; the
// latest job, non-terminal jobs and builders survive; any batch size
// deletes everything eligible.
func TestPruneKeepsVerdictsAndLatest(t *testing.T) {
	for _, batch := range []int{1, 2, 500} {
		s, _ := sweptStore(t)
		ctx := context.Background()
		enqueue(t, s, "d1", envA, JobDeploy, 1)
		finish(t, s, acquire(t, s), StatusFailed) // job 1, terminal
		enqueue(t, s, "d2", envA, JobDeploy, 2)
		enqueue(t, s, "d3", envA, JobDeploy, 3)
		l := acquire(t, s) // job 3; job 2 SKIPPED
		finish(t, s, l, StatusSuccess)
		enqueue(t, s, "d4", envB, JobDeploy, 1) // job 4, the only job of envB
		finish(t, s, acquire(t, s), StatusSuccess)
		enqueue(t, s, "d5", envA, JobTeardown, 4) // job 5, QUEUED, latest of envA

		stats, err := s.Prune(ctx, PruneRequest{Now: t0.Add(48 * time.Hour), Retention: 24 * time.Hour,
			DeliveryMaxAge: 15 * time.Minute, Batch: batch, Builders: []int64{3}})
		if err != nil {
			t.Fatal(err)
		}
		if stats.Jobs != 2 || stats.Deliveries != 5 || stats.Boots != 0 {
			t.Fatalf("batch %d: stats %+v, want 2 jobs (1, 2) and 5 deliveries", batch, stats)
		}
		jobs, err := s.Jobs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ids []int64
		for _, j := range jobs {
			ids = append(ids, j.ID)
		}
		if !slices.Equal(ids, []int64{3, 4, 5}) {
			t.Fatalf("batch %d: jobs %v left, want the builder, the queued latest and envB's latest", batch, ids)
		}
		// Defense in depth (A1-9): the watermark holds the pruned seqs, so a
		// verdict survives even the loss of the latest job.
		var mark int64
		if err := s.db.QueryRowContext(ctx, `SELECT seq FROM watermarks WHERE preview_id = ?`, envA).Scan(&mark); err != nil || mark != 2 {
			t.Fatalf("batch %d: watermark of %s = %d (%v), want 2", batch, envA, mark, err)
		}
		for _, seq := range []int64{1, 2} {
			if v, _ := enqueue(t, s, fmt.Sprintf("redelivered-%d", seq), envA, JobDeploy, seq); v != VerdictStale {
				t.Fatalf("batch %d: redelivery at pruned seq %d = %s, want stale", batch, seq, v)
			}
		}
	}
}

// Fail closed: a malformed prune request deletes nothing.
func TestPruneRefusesInvalidRequest(t *testing.T) {
	s, _ := sweptStore(t)
	for name, req := range map[string]PruneRequest{
		"no time":            {Retention: time.Hour, Batch: 1},
		"negative retention": {Now: t0, Retention: -time.Hour, Batch: 1},
		"zero batch":         {Now: t0, Retention: time.Hour},
		"bad builder":        {Now: t0, Retention: time.Hour, Batch: 1, Builders: []int64{0}},
	} {
		if _, err := s.Prune(context.Background(), req); !errors.Is(err, ErrInvalidPrune) {
			t.Errorf("%s: %v, want ErrInvalidPrune", name, err)
		}
	}
}

// Expired lists environments whose latest job is a SUCCESS deploy older
// than the TTL; a newer intent hides it.
func TestExpired(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueue(t, s, "d1", envA, JobDeploy, 1)
	finish(t, s, acquire(t, s), StatusSuccess)
	enqueue(t, s, "d2", envB, JobDeploy, 1)
	finish(t, s, acquire(t, s), StatusSuccess)
	enqueue(t, s, "d3", envB, JobTeardown, 2)
	for _, tc := range []struct {
		at   time.Time
		want []string
	}{
		{t0.Add(59 * time.Minute), nil},
		{t0.Add(time.Hour), []string{envA}},
	} {
		got, err := s.Expired(ctx, time.Hour, tc.at)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Fatalf("Expired at %s = %v, %v; want %v", tc.at, got, err, tc.want)
		}
	}
	if _, err := s.Expired(ctx, 0, t0); err == nil {
		t.Fatal("Expired with a zero TTL accepted")
	}
}

// LiveApproval names the newest live grant of the commit (the one the
// authorizer re-reads from GHES and Classify audits), and nothing once a
// revocation newer than every grant is recorded.
func TestLiveApprovalNamesTheNewestLiveGrant(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	if _, ok, err := s.LiveApproval(ctx, envA, commitA); err != nil || ok {
		t.Fatalf("no grant: live = %v, %v", ok, err)
	}
	approve(t, s, grantOf(commitA, 10))
	newer := grantOf(commitA, 12)
	newer.ApproverLogin, newer.ApproverID, newer.ReviewID = "second", 8, 120
	approve(t, s, newer)
	a, ok, err := s.LiveApproval(ctx, envA, commitA)
	want := Approval{EnvID: envA, CommitSHA: commitA, ApproverLogin: "second", ApproverID: 8, Via: ApprovalViaReview, ReviewID: 120}
	if err != nil || !ok || a != want {
		t.Fatalf("LiveApproval = %+v, %v, %v; want %+v", a, ok, err, want)
	}
	revoke(t, s, commitA, 13)
	if a, ok, err := s.LiveApproval(ctx, envA, commitA); err != nil || ok || a != (Approval{}) {
		t.Fatalf("after a newer revocation: %+v, %v, %v", a, ok, err)
	}
	for _, bad := range [][2]string{{"", commitA}, {envA, "abc"}, {envA, ""}} {
		if _, _, err := s.LiveApproval(ctx, bad[0], bad[1]); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("LiveApproval(%q, %q) = %v, want ErrInvalidGrant", bad[0], bad[1], err)
		}
	}
}
