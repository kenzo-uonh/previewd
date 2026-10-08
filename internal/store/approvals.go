package store

// Approval gating (V1 spec 3.1-3.4, docs/formal/V1-model.md section 1.3).
//
// An approval of (env, commit) is live when its newest grant is newer, by
// seq, than its newest revocation, whatever order they arrived in: a
// dismissal delivered after a newer approval does not cancel it, and an
// approval delivered after a newer dismissal is not live. Revocations are
// stored apart from grants, keyed by (env, commit), so one can precede its
// grant (A2-5):
//   - revocations: explicit revocations (dismissal, change request, label
//     removal, re-validation), with or without a grant;
//   - heads: the new-head revocation. A deploy delivery at seq s revokes
//     every other commit at s, including commits never seen yet, whose
//     grant may still be in flight. One row per environment holds the
//     newest deploy (commit, seq) and the newest deploy seq of any other
//     commit (prior_seq), which is exactly the revocation seq of every
//     commit: seq for the others, prior_seq for the head itself.
//
// A revocation applies to every grant of the commit, whoever granted it: one
// approver's dismissal voids the commit's approval until a newer grant. This
// is the model's rule, and the conservative one; AuthorizeDeploy re-reads
// GHES before anything runs.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ApprovalVia is how an approver approved.
type ApprovalVia string

// Approval paths (D-V1-3).
const (
	ApprovalViaReview ApprovalVia = "review"
	ApprovalViaLabel  ApprovalVia = "label"
)

// RevocationReason is the closed vocabulary of revocations.reason.
type RevocationReason string

// Revocation reasons. RevokedNewHead is recorded by Enqueue (heads);
// RevokedPRClosed and RevokedRevalidationUnavailable are in the vocabulary
// but no queue rule records them: a closed PR keeps its approvals, as GitHub
// does (V1-model.md A2-5), and an unavailable GHES tears down without
// revoking (D-V1-5 grace).
const (
	RevokedDismissed               RevocationReason = "dismissed"
	RevokedChangesRequested        RevocationReason = "changes_requested"
	RevokedUnlabeled               RevocationReason = "unlabeled"
	RevokedNewHead                 RevocationReason = "new_head"
	RevokedApproverRemoved         RevocationReason = "approver_removed"
	RevokedPermissionLost          RevocationReason = "permission_lost"
	RevokedRevalidationUnavailable RevocationReason = "revalidation_unavailable"
	RevokedPRClosed                RevocationReason = "pr_closed"
)

func (r RevocationReason) valid() bool {
	switch r {
	case RevokedDismissed, RevokedChangesRequested, RevokedUnlabeled, RevokedNewHead, RevokedApproverRemoved,
		RevokedPermissionLost, RevokedRevalidationUnavailable, RevokedPRClosed:
		return true
	}
	return false
}

// Approval errors.
var (
	ErrNotApproved        = errors.New("no live approval of the commit")
	ErrAlreadyClassified  = errors.New("the deploy is already classified")
	ErrInvalidGrant       = errors.New("invalid grant")
	ErrInvalidRevocation  = errors.New("invalid revocation")
	ErrInvalidInternalJob = errors.New("invalid internal job")
)

// Grant is an approval delivery as the API hands it over, with the GitHub
// truth it read in the same step: Trusted (the environment needs no
// approval, D-V1-5), OpenHead (the PR is open and Source.CommitSHA is its
// head) and the PR's Source. DeliveryID and PayloadSHA256 are its replay
// keys, as for Enqueue.
type Grant struct {
	DeliveryID    string
	PayloadSHA256 string
	EnvID         string
	Source        Source // CommitSHA is the approved commit
	Seq           int64  // delivery order of the approval
	ApproverLogin string
	ApproverID    int64
	Via           ApprovalVia
	ReviewID      int64 // 0 for a label approval
	Trusted       bool
	OpenHead      bool
}

func (g Grant) valid() bool {
	return validDeliveryKeys(g.DeliveryID, g.PayloadSHA256) && validPreviewID(g.EnvID) && g.Source.valid() && g.Seq > 0 &&
		validLogin(g.ApproverLogin) && g.ApproverID > 0 &&
		((g.Via == ApprovalViaReview && g.ReviewID > 0) || (g.Via == ApprovalViaLabel && g.ReviewID == 0))
}

// Revoke is a revocation delivery (dismissal, change request, label
// removal) as the API hands it over. Trusted is GitHub truth read in the
// same step. DeliveryID and PayloadSHA256 are its replay keys.
type Revoke struct {
	DeliveryID    string
	PayloadSHA256 string
	EnvID         string
	Repo          string
	PRNumber      int64
	CommitSHA     string
	Seq           int64 // delivery order of the revocation
	Reason        RevocationReason
	Trusted       bool
}

func (r Revoke) valid() bool {
	return validDeliveryKeys(r.DeliveryID, r.PayloadSHA256) && validPreviewID(r.EnvID) && len(r.Repo) >= 3 && len(r.Repo) <= maxRepoLen && r.PRNumber > 0 &&
		validCommit(r.CommitSHA) && r.Seq > 0 && r.Reason.valid() && r.Reason != RevokedNewHead
}

// revokedSeqSQL is the seq at which (?1 env, ?2 commit) is revoked: the
// newest of its explicit revocation and its new-head revocation; 0 if none.
const revokedSeqSQL = `max(
	coalesce((SELECT r.revoked_seq FROM revocations r WHERE r.preview_id = ?1 AND r.commit_sha = ?2), 0),
	coalesce((SELECT CASE WHEN h.commit_sha = ?2 THEN h.prior_seq ELSE h.seq END FROM heads h WHERE h.preview_id = ?1), 0))`

// queryNewestLiveGrant selects the newest grant of (?1 env, ?2 commit) newer
// than every revocation of it.
const queryNewestLiveGrant = `
	SELECT approver_login, approver_id, via FROM approvals
	WHERE preview_id = ?1 AND commit_sha = ?2 AND granted_seq > ` + revokedSeqSQL + `
	ORDER BY granted_seq DESC, id DESC LIMIT 1`

// liveGrant is the newest grant of a live approval.
type liveGrant struct {
	ApproverLogin string
	ApproverID    int64
	Via           ApprovalVia
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// newestLiveGrant returns the newest grant of (envID, commit) when the
// approval is live: a grant newer than every revocation of it.
func newestLiveGrant(ctx context.Context, q rowQuerier, envID, commit string) (liveGrant, bool, error) {
	var g liveGrant
	var via string
	err := q.QueryRowContext(ctx, queryNewestLiveGrant, envID, commit).Scan(&g.ApproverLogin, &g.ApproverID, &via)
	if errors.Is(err, sql.ErrNoRows) {
		return liveGrant{}, false, nil
	}
	if err != nil {
		return liveGrant{}, false, fmt.Errorf("live approval of %s at %s: %w", envID, commit, err)
	}
	g.Via = ApprovalVia(via)
	return g, true, nil
}

// ApprovalLive reports whether (envID, commitSHA) has a grant newer than
// every revocation of it, by seq. The Revalidator reads it for every running
// environment (D-V1-5), and AuthorizeDeploy's GHES-unavailable branch for the
// running version (A2-6).
func (s *Store) ApprovalLive(ctx context.Context, envID, commitSHA string) (bool, error) {
	if !validPreviewID(envID) || !validCommit(commitSHA) {
		return false, fmt.Errorf("approval live: %w: %s at %s", ErrInvalidGrant, quoted(envID), quoted(commitSHA))
	}
	_, live, err := newestLiveGrant(ctx, s.db, envID, commitSHA)
	return live, err
}

// recordNewHead is the new-head revocation of an accepted deploy delivery:
// every other commit of the environment is revoked at its seq. A live
// approval it ends gets an approval_revoked audit row.
func recordNewHead(ctx context.Context, tx *sql.Tx, d Delivery) error {
	commits, err := grantedCommits(ctx, tx, d.EnvID, d.Source.CommitSHA)
	if err != nil {
		return err
	}
	var wasLive []string
	for _, c := range commits {
		_, live, err := newestLiveGrant(ctx, tx, d.EnvID, c)
		if err != nil {
			return err
		}
		if live {
			wasLive = append(wasLive, c)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO heads (preview_id, commit_sha, seq, prior_seq) VALUES (?, ?, ?, 0)
		ON CONFLICT (preview_id) DO UPDATE SET
			prior_seq = CASE WHEN heads.commit_sha = excluded.commit_sha THEN heads.prior_seq ELSE heads.seq END,
			commit_sha = excluded.commit_sha,
			seq = excluded.seq
		WHERE excluded.seq > heads.seq`, d.EnvID, d.Source.CommitSHA, d.Seq); err != nil {
		return fmt.Errorf("enqueue: record new head of %s: %w", d.EnvID, err)
	}
	for _, c := range wasLive {
		_, live, err := newestLiveGrant(ctx, tx, d.EnvID, c)
		if err != nil {
			return err
		}
		if live {
			continue // granted after this push was sent
		}
		if err := appendAudit(ctx, tx, AuditEvent{
			Kind: AuditApprovalRevoked, EnvID: d.EnvID, Repo: d.Source.Repo, PRNumber: d.Source.PRNumber,
			CommitSHA: c, Detail: string(RevokedNewHead),
		}, d.ReceivedAt); err != nil {
			return err
		}
	}
	return nil
}

// grantedCommits lists the commits of envID other than except that have a
// grant, sorted.
func grantedCommits(ctx context.Context, tx *sql.Tx, envID, except string) (commits []string, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT commit_sha FROM approvals WHERE preview_id = ? AND commit_sha <> ? ORDER BY commit_sha`, envID, except)
	if err != nil {
		return nil, fmt.Errorf("granted commits of %s: %w", envID, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close granted commits of %s: %w", envID, closeErr))
		}
	}()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("scan granted commit of %s: %w", envID, err)
		}
		commits = append(commits, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("granted commits of %s: %w", envID, err)
	}
	return commits, nil
}

// recordRevocation raises the revocation seq of (envID, commit) to seq.
func recordRevocation(ctx context.Context, tx *sql.Tx, envID, commit string, seq int64, reason RevocationReason, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO revocations (preview_id, commit_sha, revoked_seq, revoked_at, reason) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (preview_id, commit_sha) DO UPDATE SET
			revoked_seq = excluded.revoked_seq, revoked_at = excluded.revoked_at, reason = excluded.reason
		WHERE excluded.revoked_seq > revocations.revoked_seq`,
		envID, commit, seq, now.UnixMilli(), string(reason)); err != nil {
		return fmt.Errorf("record revocation of %s at %s: %w", envID, commit, err)
	}
	return nil
}

// Approve records a grant, its delivery and its audit row (kind
// approval_granted, the approver as actor) in one transaction. A delivery
// whose ID or signed body was already recorded is a replay and changes
// nothing: a captured approval resent under a fresh delivery ID cannot
// revive it after a dismissal. When the environment is not trusted
// and the approval is live, it judges the latest job (V1-model.md A1-3):
//   - the parked deploy of the commit becomes QUEUED (same seq);
//   - otherwise, when the commit is the open head and the latest job does not
//     already deploy it, a deploy is queued (origin approval, seq MaxSeq + 1).
//
// It returns the verdict (accepted or replay) and the unparked or queued
// job, or 0. now is the receipt time.
func (s *Store) Approve(ctx context.Context, g Grant, now time.Time, audit AuditEvent) (verdict Verdict, jobID int64, err error) {
	if _, err := s.requireSwept(); err != nil {
		return "", 0, err
	}
	if !g.valid() || !validTime(now) {
		return "", 0, ErrInvalidGrant
	}
	c := g.Source.CommitSHA
	if err := audit.matches(AuditApprovalGranted, g.EnvID, g.Source.Repo, g.Source.PRNumber, c); err != nil {
		return "", 0, err
	}
	if audit.ActorID != g.ApproverID || audit.ActorLogin != g.ApproverLogin || audit.Detail != string(g.Via) {
		return "", 0, fmt.Errorf("%w: approval_granted names %s#%d (%s), the grant %s#%d (%s)", ErrInvalidAudit,
			quoted(audit.ActorLogin), audit.ActorID, quoted(audit.Detail), quoted(g.ApproverLogin), g.ApproverID, g.Via)
	}

	err = s.inTx(ctx, "approve", func(tx *sql.Tx) error {
		if replay, err := seenDelivery(ctx, tx, g.DeliveryID, g.PayloadSHA256); err != nil || replay {
			verdict = VerdictReplay
			return err
		}
		verdict = VerdictAccepted
		if err := recordDelivery(ctx, tx, g.DeliveryID, g.PayloadSHA256, g.EnvID, g.Seq, VerdictAccepted, now); err != nil {
			return fmt.Errorf("approve: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO approvals (preview_id, repo, pr_number, commit_sha, approver_login, approver_id, via, review_id, granted_seq, granted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (preview_id, commit_sha, approver_id, via) DO UPDATE SET
				repo = excluded.repo, pr_number = excluded.pr_number, approver_login = excluded.approver_login,
				review_id = excluded.review_id, granted_seq = excluded.granted_seq, granted_at = excluded.granted_at
			WHERE excluded.granted_seq > approvals.granted_seq`,
			g.EnvID, g.Source.Repo, g.Source.PRNumber, c, g.ApproverLogin, g.ApproverID, string(g.Via), g.ReviewID,
			g.Seq, now.UnixMilli()); err != nil {
			return fmt.Errorf("approve: record grant of %s at %s: %w", g.EnvID, c, err)
		}
		if err := appendAudit(ctx, tx, audit, now); err != nil {
			return err
		}
		if g.Trusted {
			return nil
		}
		if _, live, err := newestLiveGrant(ctx, tx, g.EnvID, c); err != nil || !live {
			return err
		}
		latest, found, err := latestJob(ctx, tx, g.EnvID)
		if err != nil {
			return err
		}
		switch {
		case found && latest.Status == StatusPendingApproval && latest.Source.CommitSHA == c:
			if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'QUEUED' WHERE id = ? AND status = 'PENDING_APPROVAL'`, latest.ID); err != nil {
				return fmt.Errorf("approve: unpark job %d: %w", latest.ID, err)
			}
			jobID = latest.ID
		case g.OpenHead && !headIntentPresent(latest, found, c):
			if jobID, err = insertInternal(ctx, tx, g.EnvID, JobDeploy, OriginApproval, g.Source, now); err != nil {
				return fmt.Errorf("approve: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return verdict, jobID, nil
}

// Revoke records a revocation, its delivery and its audit row (kind
// approval_revoked, detail the reason) in one transaction; a replayed
// delivery changes nothing. When the environment is not
// trusted, no grant of the commit stays live, and the latest job deploys the
// commit (QUEUED, IN_PROGRESS, PENDING_APPROVAL or SUCCESS), a teardown of
// it is queued (origin revocation, seq MaxSeq + 1). When the latest job
// deploys another commit, that intent removes the revoked version itself,
// and a teardown above it would skip the new head (V1-model.md A2-1).
//
// It returns the verdict (accepted or replay) and the teardown job, or 0.
// now is the receipt time.
func (s *Store) Revoke(ctx context.Context, r Revoke, now time.Time, audit AuditEvent) (verdict Verdict, teardownJobID int64, err error) {
	if _, err := s.requireSwept(); err != nil {
		return "", 0, err
	}
	if !r.valid() || !validTime(now) {
		return "", 0, ErrInvalidRevocation
	}
	if err := audit.matches(AuditApprovalRevoked, r.EnvID, r.Repo, r.PRNumber, r.CommitSHA); err != nil {
		return "", 0, err
	}
	if audit.Detail != string(r.Reason) {
		return "", 0, fmt.Errorf("%w: approval_revoked detail %s, reason %s", ErrInvalidAudit, quoted(audit.Detail), r.Reason)
	}

	err = s.inTx(ctx, "revoke", func(tx *sql.Tx) error {
		if replay, err := seenDelivery(ctx, tx, r.DeliveryID, r.PayloadSHA256); err != nil || replay {
			verdict = VerdictReplay
			return err
		}
		verdict = VerdictAccepted
		if err := recordDelivery(ctx, tx, r.DeliveryID, r.PayloadSHA256, r.EnvID, r.Seq, VerdictAccepted, now); err != nil {
			return fmt.Errorf("revoke: %w", err)
		}
		if err := recordRevocation(ctx, tx, r.EnvID, r.CommitSHA, r.Seq, r.Reason, now); err != nil {
			return fmt.Errorf("revoke: %w", err)
		}
		if err := appendAudit(ctx, tx, audit, now); err != nil {
			return err
		}
		if r.Trusted {
			return nil
		}
		if _, live, err := newestLiveGrant(ctx, tx, r.EnvID, r.CommitSHA); err != nil || live {
			return err
		}
		latest, found, err := latestJob(ctx, tx, r.EnvID)
		if err != nil || !headIntentPresent(latest, found, r.CommitSHA) {
			return err
		}
		if teardownJobID, err = insertInternal(ctx, tx, r.EnvID, JobTeardown, OriginRevocation, latest.Source, now); err != nil {
			return fmt.Errorf("revoke: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return verdict, teardownJobID, nil
}

// EnqueueInternal queues a teardown of the latest job's commit: origin
// revalidation (the Revalidator found the environment no longer allowed, or
// GHES unavailable past the grace) or ttl (the environment expired). With a
// reason (revalidation only), a live approval of that commit is revoked at
// now's UUIDv1 ticks in the same transaction: GitHub truth now voids every
// grant it sent so far. The audit row (kind teardown for revalidation,
// ttl_expired for ttl) records the commit; one left empty is filled in.
//
// It returns the teardown job.
func (s *Store) EnqueueInternal(ctx context.Context, envID string, origin Origin, reason RevocationReason, now time.Time, audit AuditEvent) (int64, error) {
	if _, err := s.requireSwept(); err != nil {
		return 0, err
	}
	kind := AuditTeardown
	switch {
	case !validPreviewID(envID) || !validTime(now):
		return 0, fmt.Errorf("%w: environment %s", ErrInvalidInternalJob, quoted(envID))
	case origin == OriginTTL && reason == "":
		kind = AuditTTLExpired
	case origin == OriginRevalidation && (reason == "" || (reason.valid() && reason != RevokedNewHead)):
	default:
		return 0, fmt.Errorf("%w: origin %s, reason %s", ErrInvalidInternalJob, quoted(string(origin)), quoted(string(reason)))
	}

	var jobID int64
	err := s.inTx(ctx, "enqueue internal", func(tx *sql.Tx) error {
		latest, found, err := latestJob(ctx, tx, envID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("enqueue internal %s teardown of %s: %w", origin, envID, ErrNoJob)
		}
		src := latest.Source
		if audit.CommitSHA == "" {
			audit.CommitSHA = src.CommitSHA
		}
		if err := audit.matches(kind, envID, src.Repo, src.PRNumber, src.CommitSHA); err != nil {
			return err
		}
		if reason != "" {
			if _, live, err := newestLiveGrant(ctx, tx, envID, src.CommitSHA); err != nil {
				return err
			} else if live {
				if err := recordRevocation(ctx, tx, envID, src.CommitSHA, seqAt(now), reason, now); err != nil {
					return fmt.Errorf("enqueue internal: %w", err)
				}
				if err := appendAudit(ctx, tx, AuditEvent{
					Kind: AuditApprovalRevoked, EnvID: envID, Repo: src.Repo, PRNumber: src.PRNumber,
					CommitSHA: src.CommitSHA, Detail: string(reason),
				}, now); err != nil {
					return err
				}
			}
		}
		if jobID, err = insertInternal(ctx, tx, envID, JobTeardown, origin, src, now); err != nil {
			return fmt.Errorf("enqueue internal: %w", err)
		}
		return appendAudit(ctx, tx, audit, now)
	})
	if err != nil {
		return 0, err
	}
	return jobID, nil
}

// Classify records AuthorizeDeploy's verdict on a leased, unclassified
// deploy, with its audit row, in one transaction:
//   - trusted (GHES: same repository, opener with write access): kind
//     trusted_deploy, the opener as actor;
//   - untrusted only with a live approval of the lease's commit, read in the
//     same transaction (ErrNotApproved otherwise, nothing changed): kind
//     untrusted_deploy, the approver of the newest live grant as actor.
//
// The audit row carries the wall clock.
func (s *Store) Classify(ctx context.Context, l Lease, trust Trust) error {
	if _, err := s.requireSwept(); err != nil {
		return err
	}
	if trust != TrustTrusted && trust != TrustUntrusted {
		return fmt.Errorf("classify job %d: trust %s is not trusted or untrusted", l.JobID, quoted(string(trust)))
	}
	return s.inTx(ctx, "classify", func(tx *sql.Tx) error {
		j, err := leasedDeploy(ctx, tx, "classify", l)
		if err != nil {
			return err
		}
		src := j.Source
		ev := AuditEvent{Kind: AuditTrustedDeploy, EnvID: j.EnvID, Repo: src.Repo, PRNumber: src.PRNumber,
			CommitSHA: src.CommitSHA, ActorLogin: src.OpenerLogin, ActorID: src.OpenerID, Detail: auditDetailWriteAccess}
		if trust == TrustUntrusted {
			g, live, err := newestLiveGrant(ctx, tx, j.EnvID, src.CommitSHA)
			if err != nil {
				return err
			}
			if !live {
				return fmt.Errorf("classify job %d untrusted: %w", l.JobID, ErrNotApproved)
			}
			ev.Kind, ev.ActorLogin, ev.ActorID, ev.Detail = AuditUntrustedDeploy, g.ApproverLogin, g.ApproverID, string(g.Via)
		}
		if err := updateLease(ctx, tx, "classify", l,
			`UPDATE jobs SET trust = ? WHERE id = ? AND status = 'IN_PROGRESS' AND lease_epoch = ?`,
			string(trust), l.JobID, l.Epoch); err != nil {
			return err
		}
		return appendAudit(ctx, tx, ev, time.Now())
	})
}

// Park records AuthorizeDeploy's refusal of a leased, unclassified deploy:
// IN_PROGRESS -> PENDING_APPROVAL, with a deploy_refused audit row
// (previewd as actor, the wall clock). The caller has already destroyed the
// version it supersedes. A parked job is not a lock: a newer intent skips
// it, an approval of its exact commit re-queues it.
func (s *Store) Park(ctx context.Context, l Lease) error {
	if _, err := s.requireSwept(); err != nil {
		return err
	}
	return s.inTx(ctx, "park", func(tx *sql.Tx) error {
		j, err := leasedDeploy(ctx, tx, "park", l)
		if err != nil {
			return err
		}
		if err := updateLease(ctx, tx, "park", l,
			`UPDATE jobs SET status = 'PENDING_APPROVAL' WHERE id = ? AND status = 'IN_PROGRESS' AND lease_epoch = ?`,
			l.JobID, l.Epoch); err != nil {
			return err
		}
		src := j.Source
		return appendAudit(ctx, tx, AuditEvent{Kind: AuditDeployRefused, EnvID: j.EnvID, Repo: src.Repo,
			PRNumber: src.PRNumber, CommitSHA: src.CommitSHA, Detail: auditDetailNotApproved}, time.Now())
	})
}

// leasedDeploy reads the unclassified deploy l holds.
func leasedDeploy(ctx context.Context, tx *sql.Tx, what string, l Lease) (Job, error) {
	j, err := leasedJob(ctx, tx, what, l)
	if err != nil {
		return Job{}, err
	}
	if j.Type != JobDeploy {
		return Job{}, fmt.Errorf("%s job %d: a %s is not authorized", what, l.JobID, j.Type)
	}
	if j.Trust != TrustUnclassified {
		return Job{}, fmt.Errorf("%s job %d (%s): %w", what, l.JobID, j.Trust, ErrAlreadyClassified)
	}
	return j, nil
}
