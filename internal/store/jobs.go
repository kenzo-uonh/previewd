package store

// The durable job queue: the SQLite implementation of db_jobs in
// docs/formal/previewd.tla. Each exported operation is one IMMEDIATE
// transaction and implements one transition of the model:
//
//	Enqueue          ReceiveWebhook deploy/teardown (replay protection by
//	                 delivery ID and by payload, D1 stale rule against the
//	                 watermark too, new_head revocation)
//	Approve, Revoke  ReceiveWebhook grant/revoke (approvals.go)
//	Acquire          AcquireJob (newest intent wins, older ones SKIPPED)
//	Classify, Park   AuthorizeDeploy allow and park (approvals.go)
//	Requeue          AuthorizeDeploy GHES unavailable, ExecuteTeardown
//	                 transient failure (never FAILED)
//	Finish, Fail     CommitDeploy, CommitTeardown, deploy failure rollback
//	                 (Fail records the step that failed)
//	EnqueueInternal  Revalidate, Expire (approvals.go)
//	Prune            Prune (maintenance.go)
//	StartupSweep     StartupSweep (D2, D3)
//
// The per-environment lock is the IN_PROGRESS row itself, enforced by the
// partial unique index jobs_one_in_progress. A lease carries the boot epoch
// it was taken in; any operation on a lease from an earlier boot, or on a
// job the sweep already rewrote, fails with ErrLeaseLost and changes nothing.
//
// Every internal job (origin other than webhook) takes seq = MaxSeq(env) + 1,
// one UUIDv1 tick above every job and watermark of its environment: it
// supersedes every recorded intent and loses to any delivery GitHub sent
// later, even one still in flight (V1-model.md A2-2).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// JobType is the intent of a job.
type JobType string

// Job types.
const (
	JobDeploy   JobType = "deploy"
	JobTeardown JobType = "teardown"
)

// JobStatus is the lifecycle state of a job.
type JobStatus string

// Job statuses. SUCCESS, FAILED and SKIPPED are terminal, except that the
// sweep re-arms a latest SUCCESS deploy whose environment it destroyed.
// PENDING_APPROVAL is neither terminal, nor acquirable, nor a lock.
const (
	StatusPendingApproval JobStatus = "PENDING_APPROVAL"
	StatusQueued          JobStatus = "QUEUED"
	StatusInProgress      JobStatus = "IN_PROGRESS"
	StatusSuccess         JobStatus = "SUCCESS"
	StatusFailed          JobStatus = "FAILED"
	StatusSkipped         JobStatus = "SKIPPED"
)

// Origin says what created a job.
type Origin string

// Job origins. Only a webhook job carries a GitHub delivery seq; the others
// are internal (seq = MaxSeq + 1).
const (
	OriginWebhook      Origin = "webhook"
	OriginApproval     Origin = "approval"     // deploy of the approved open head
	OriginRevocation   Origin = "revocation"   // teardown after a revoked approval
	OriginRevalidation Origin = "revalidation" // teardown after a failed re-validation
	OriginTTL          Origin = "ttl"          // teardown after the environment TTL
)

// Trust is the classification AuthorizeDeploy gave a deploy.
type Trust string

// Trust levels. A deploy is unclassified until Classify; a teardown always.
const (
	TrustUnclassified Trust = "unclassified"
	TrustTrusted      Trust = "trusted"   // same repository, opener with write access
	TrustUntrusted    Trust = "untrusted" // runs on a live approval of its commit
)

// Failure is the closed vocabulary of jobs.failure, never free text.
type Failure string

// Deploy failures. Only FailureInterrupted is recorded by the store itself
// (the sweep); the reconciler records the others.
const (
	FailureNone         Failure = ""
	FailureFetch        Failure = "fetch"
	FailurePreflight    Failure = "preflight"
	FailureBuild        Failure = "build"
	FailureStage        Failure = "stage"
	FailureStart        Failure = "start"
	FailureRoute        Failure = "route"
	FailureCommit       Failure = "commit"
	FailureUnauthorized Failure = "unauthorized"
	FailureDiskFloor    Failure = "disk_floor"
	FailureInterrupted  Failure = "interrupted"
)

// Verdict is the outcome of one delivery.
type Verdict string

// Delivery verdicts.
const (
	VerdictAccepted Verdict = "accepted"
	VerdictStale    Verdict = "stale"
	VerdictReplay   Verdict = "replay"
)

// Queue errors.
var (
	ErrLeaseLost          = errors.New("lease lost: the job was swept or belongs to an earlier boot")
	ErrNotSwept           = errors.New("startup sweep has not run")
	ErrInvalidDelivery    = errors.New("invalid delivery")
	ErrInvalidObservation = errors.New("invalid observation")
	ErrInvalidTime        = errors.New("invalid time: not after the Unix epoch")
	ErrTeardownCannotFail = errors.New("a teardown never fails: requeue it")
	ErrDeployCannotRetry  = errors.New("a classified deploy is never requeued: finish it as FAILED")
	ErrNoJob              = errors.New("the environment has no job")
	ErrInvalidFailure     = errors.New("invalid failure kind: not a deploy step of the closed vocabulary")
)

const (
	maxPreviewIDLen  = 63
	maxDeliveryIDLen = 64
	maxRepoLen       = 140
	maxLoginLen      = 39
	maxCloneURLLen   = 2048

	// uuidEpochOffset is the number of 100 ns intervals between the UUID
	// epoch (1582-10-15) and the Unix epoch.
	uuidEpochOffset = int64(122_192_928_000_000_000)
)

// seqAt is t in UUIDv1 timestamp units (100 ns since 1582-10-15): the seq
// GitHub gives a delivery sent at t, and the seq of a revocation previewd
// records itself at t.
func seqAt(t time.Time) int64 {
	return t.UnixNano()/100 + uuidEpochOffset
}

// Source is what a deploy needs to build the environment, and who opened the
// pull request. The API validates it (internal/validate) before it reaches
// the queue; the store only bounds it. Trust is never read from it: the
// authorizer reads GHES (D-V1-5).
type Source struct {
	Repo        string
	HeadRepo    string // "" when the head repository (a fork) was deleted
	PRNumber    int64
	OpenerLogin string
	OpenerID    int64
	CommitSHA   string
	CloneURL    string
}

// Delivery is one signed webhook delivery. ID is the delivery GUID and
// PayloadSHA256 the hex SHA-256 of the signed body: both are replay keys,
// the second because GitHub does not sign the delivery header, so a captured
// body resent under a new ID is still a replay. Seq orders intents of the
// same environment: a delivery whose Seq is not above every job and
// watermark already recorded for EnvID is stale.
type Delivery struct {
	ID            string
	PayloadSHA256 string
	EnvID         string
	Type          JobType
	Seq           int64
	Source        Source
	ReceivedAt    time.Time
}

// Job is one row of the queue.
type Job struct {
	ID         int64
	EnvID      string
	Type       JobType
	Origin     Origin
	Seq        int64
	Status     JobStatus
	Trust      Trust
	Attempts   int64
	NotBefore  int64 // Unix milliseconds; Acquire skips the job before then
	LeaseEpoch int64
	CreatedAt  int64 // Unix milliseconds
	FinishedAt int64 // Unix milliseconds, 0 while not terminal
	Failure    Failure
	Source     Source
}

// Lease is a worker's claim on one IN_PROGRESS job.
type Lease struct {
	JobID    int64
	EnvID    string
	Type     JobType
	Seq      int64
	Epoch    int64
	Attempts int64
	Source   Source
}

// Observation is what the host holds for one environment at startup.
// JobID names the deploy job that built the container (0 when unknown, e.g.
// a leftover no job tracks).
type Observation struct {
	EnvID          string
	Running        bool
	NetworkBound   bool
	SecretsMounted bool
	Routed         bool // a route document exists
	JobID          int64
}

func (o Observation) exists() bool {
	return o.Running || o.NetworkBound || o.SecretsMounted || o.Routed
}

func (o Observation) intact() bool {
	return o.Running && o.NetworkBound && o.SecretsMounted && o.Routed
}

// SweepResult lists the environments the caller must destroy, sorted, before
// any worker or webhook is served.
type SweepResult struct {
	Epoch   int64
	Destroy []string
}

func validPreviewID(id string) bool {
	return id != "" && len(id) <= maxPreviewIDLen
}

func validType(t JobType) bool {
	return t == JobDeploy || t == JobTeardown
}

func validTime(t time.Time) bool {
	return t.UnixMilli() > 0
}

func validCommit(sha string) bool {
	return (len(sha) == 40 || len(sha) == 64) && isLowerHex(sha)
}

func validLogin(login string) bool {
	return login != "" && len(login) <= maxLoginLen
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// valid bounds a source that comes from GitHub now: every field known.
func (src Source) valid() bool {
	return len(src.Repo) >= 3 && len(src.Repo) <= maxRepoLen && len(src.HeadRepo) <= maxRepoLen &&
		src.PRNumber > 0 && validLogin(src.OpenerLogin) && src.OpenerID > 0 &&
		validCommit(src.CommitSHA) && src.CloneURL != "" && len(src.CloneURL) <= maxCloneURLLen
}

func (d Delivery) valid() bool {
	return d.ID != "" && len(d.ID) <= maxDeliveryIDLen &&
		len(d.PayloadSHA256) == 64 && isLowerHex(d.PayloadSHA256) &&
		validPreviewID(d.EnvID) && validType(d.Type) && d.Seq > 0 &&
		d.Source.valid() && validTime(d.ReceivedAt)
}

// Epoch returns the current boot epoch, 0 before StartupSweep.
func (s *Store) Epoch() int64 {
	return s.epoch.Load()
}

func (s *Store) requireSwept() (int64, error) {
	epoch := s.epoch.Load()
	if epoch == 0 {
		return 0, ErrNotSwept
	}
	return epoch, nil
}

// inTx runs fn in one IMMEDIATE transaction (the DSN sets _txlock) and
// commits it, or rolls it back if fn or the commit fails.
func (s *Store) inTx(ctx context.Context, what string, fn func(*sql.Tx) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: begin: %w", what, err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("%s: rollback: %w", what, rbErr))
			}
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: commit: %w", what, err)
	}
	return nil
}

// jobColumns is the column list scanJob reads, in its order.
const jobColumns = `id, preview_id, type, origin, seq, status, trust, attempts, not_before, lease_epoch,
	created_at, finished_at, failure, repo, head_repo, pr_number, opener_login, opener_id, commit_sha, clone_url`

// Job queries: constant SQL, every value bound.
const (
	queryLatestJob = `SELECT ` + jobColumns + ` FROM jobs WHERE preview_id = ? ORDER BY seq DESC LIMIT 1`
	queryJobByID   = `SELECT ` + jobColumns + ` FROM jobs WHERE id = ?`
	queryAllJobs   = `SELECT ` + jobColumns + ` FROM jobs ORDER BY id`
	// queryRunning: environments whose latest job is a SUCCESS deploy, the
	// builder of what runs there, in environment order.
	queryRunning = `SELECT ` + jobColumns + ` FROM jobs j
		WHERE j.type = 'deploy' AND j.status = 'SUCCESS'
		  AND NOT EXISTS (SELECT 1 FROM jobs n WHERE n.preview_id = j.preview_id AND n.seq > j.seq)
		ORDER BY j.preview_id`
	// queryNewestSuccess: the newest SUCCESS job of an environment.
	queryNewestSuccess = `SELECT ` + jobColumns + ` FROM jobs WHERE preview_id = ? AND status = 'SUCCESS' ORDER BY seq DESC LIMIT 1`
)

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(r rowScanner) (Job, error) {
	var j Job
	var typ, origin, status, trust, failure string
	src := &j.Source
	if err := r.Scan(&j.ID, &j.EnvID, &typ, &origin, &j.Seq, &status, &trust, &j.Attempts, &j.NotBefore, &j.LeaseEpoch,
		&j.CreatedAt, &j.FinishedAt, &failure, &src.Repo, &src.HeadRepo, &src.PRNumber, &src.OpenerLogin, &src.OpenerID,
		&src.CommitSHA, &src.CloneURL); err != nil {
		return Job{}, err
	}
	j.Type, j.Origin, j.Status, j.Trust, j.Failure = JobType(typ), Origin(origin), JobStatus(status), Trust(trust), Failure(failure)
	return j, nil
}

// maxSeq is MaxSeq(env): the highest seq ever recorded for env, from its jobs
// and its watermark. The stale rule and every internal job read it.
func maxSeq(ctx context.Context, tx *sql.Tx, envID string) (int64, error) {
	var seq int64
	if err := tx.QueryRowContext(ctx, `
		SELECT max(
			coalesce((SELECT max(seq) FROM jobs WHERE preview_id = ?1), 0),
			coalesce((SELECT seq FROM watermarks WHERE preview_id = ?1), 0))`, envID).Scan(&seq); err != nil {
		return 0, fmt.Errorf("max seq of %s: %w", envID, err)
	}
	return seq, nil
}

// latestJob is Latest(env): the job of env with the highest seq.
func latestJob(ctx context.Context, tx *sql.Tx, envID string) (Job, bool, error) {
	j, err := scanJob(tx.QueryRowContext(ctx, queryLatestJob, envID))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("latest job of %s: %w", envID, err)
	}
	return j, true, nil
}

// headIntentPresent: the latest intent of the environment already deploys
// commit. A grant then needs no new job (A1-3), and a revocation of commit
// needs a teardown (A2-1). Judged on the latest job only: an older queued
// deploy behind a newer intent will be skipped, and a running version behind
// a newer deploy will be replaced or removed by it.
func headIntentPresent(latest Job, found bool, commit string) bool {
	return found && latest.Type == JobDeploy && latest.Source.CommitSHA == commit &&
		(latest.Status == StatusQueued || latest.Status == StatusInProgress ||
			latest.Status == StatusPendingApproval || latest.Status == StatusSuccess)
}

// newJob is a job about to be inserted QUEUED.
type newJob struct {
	EnvID     string
	Type      JobType
	Origin    Origin
	Seq       int64
	CreatedAt time.Time
	Source    Source
}

func insertJob(ctx context.Context, tx *sql.Tx, j newJob) (int64, error) {
	src := j.Source
	res, err := tx.ExecContext(ctx, `
		INSERT INTO jobs (preview_id, type, origin, seq, status, created_at,
			repo, head_repo, pr_number, opener_login, opener_id, commit_sha, clone_url)
		VALUES (?, ?, ?, ?, 'QUEUED', ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.EnvID, string(j.Type), string(j.Origin), j.Seq, j.CreatedAt.UnixMilli(),
		src.Repo, src.HeadRepo, src.PRNumber, src.OpenerLogin, src.OpenerID, src.CommitSHA, src.CloneURL)
	if err != nil {
		return 0, fmt.Errorf("insert %s %s job of %s: %w", j.Origin, j.Type, j.EnvID, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert %s %s job of %s: job id: %w", j.Origin, j.Type, j.EnvID, err)
	}
	return id, nil
}

// insertInternal appends an internal job just above MaxSeq(env) (A2-2).
func insertInternal(ctx context.Context, tx *sql.Tx, envID string, typ JobType, origin Origin, src Source, now time.Time) (int64, error) {
	top, err := maxSeq(ctx, tx, envID)
	if err != nil {
		return 0, err
	}
	return insertJob(ctx, tx, newJob{EnvID: envID, Type: typ, Origin: origin, Seq: top + 1, CreatedAt: now, Source: src})
}

// Enqueue records a delivery. A delivery whose ID or payload was already seen
// is a replay and changes nothing. A delivery is stale when its Seq is not
// above MaxSeq of its environment, whatever the status of the job that holds
// it (D1): a newer intent that failed or was skipped still supersedes it, and
// a pruned one left its watermark. Otherwise a QUEUED job is appended and its
// ID returned. An accepted deploy is the PR's new head: in the same
// transaction it revokes, at its seq, the approvals of every other commit
// (new_head). It queues no teardown: the deploy itself replaces the old
// version, or removes it when parked.
func (s *Store) Enqueue(ctx context.Context, d Delivery) (Verdict, int64, error) {
	if _, err := s.requireSwept(); err != nil {
		return "", 0, err
	}
	if !d.valid() {
		return "", 0, ErrInvalidDelivery
	}

	var verdict Verdict
	var jobID int64
	err := s.inTx(ctx, "enqueue", func(tx *sql.Tx) error {
		var err error
		verdict, jobID, err = enqueueTx(ctx, tx, d)
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return verdict, jobID, nil
}

// enqueueTx is Enqueue's transaction body, on a valid delivery.
func enqueueTx(ctx context.Context, tx *sql.Tx, d Delivery) (Verdict, int64, error) {
	if replay, err := seenDelivery(ctx, tx, d.ID, d.PayloadSHA256); err != nil || replay {
		return VerdictReplay, 0, err
	}
	top, err := maxSeq(ctx, tx, d.EnvID)
	if err != nil {
		return "", 0, fmt.Errorf("enqueue: order check: %w", err)
	}
	verdict := VerdictAccepted
	if d.Seq <= top {
		verdict = VerdictStale
	}
	if err := recordDelivery(ctx, tx, d.ID, d.PayloadSHA256, d.EnvID, d.Seq, verdict, d.ReceivedAt); err != nil {
		return "", 0, fmt.Errorf("enqueue: %w", err)
	}
	if verdict == VerdictStale {
		return verdict, 0, nil
	}
	jobID, err := insertJob(ctx, tx, newJob{EnvID: d.EnvID, Type: d.Type, Origin: OriginWebhook, Seq: d.Seq, CreatedAt: d.ReceivedAt, Source: d.Source})
	if err != nil {
		return "", 0, fmt.Errorf("enqueue: %w", err)
	}
	if d.Type == JobDeploy {
		if err := recordNewHead(ctx, tx, d); err != nil {
			return "", 0, err
		}
	}
	return verdict, jobID, nil
}

// seenDelivery is the replay rule: a delivery whose ID or signed body was
// already recorded. The body counts because GitHub does not sign the
// delivery header: a captured body resent under a fresh ID is a replay.
func seenDelivery(ctx context.Context, tx *sql.Tx, id, payloadSHA256 string) (bool, error) {
	var seen int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deliveries WHERE delivery_id = ? OR payload_sha256 = ?`, id, payloadSHA256).Scan(&seen); err != nil {
		return false, fmt.Errorf("replay check: %w", err)
	}
	return seen > 0, nil
}

func recordDelivery(ctx context.Context, tx *sql.Tx, id, payloadSHA256, envID string, seq int64, verdict Verdict, at time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries (delivery_id, payload_sha256, preview_id, seq, verdict, received_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, payloadSHA256, envID, seq, string(verdict), at.UnixMilli()); err != nil {
		return fmt.Errorf("record delivery %s: %w", id, err)
	}
	return nil
}

func validDeliveryKeys(id, payloadSHA256 string) bool {
	return id != "" && len(id) <= maxDeliveryIDLen && len(payloadSHA256) == 64 && isLowerHex(payloadSHA256)
}

// Acquire leases the next job. An environment is ready when it has no
// IN_PROGRESS job and its newest QUEUED job is due at now. Among ready
// environments, the one whose newest QUEUED job has the lowest ID goes
// first. In the same transaction the newest QUEUED job becomes IN_PROGRESS,
// and every older QUEUED or PENDING_APPROVAL job of that environment becomes
// SKIPPED. ok is false when nothing is ready.
func (s *Store) Acquire(ctx context.Context, now time.Time) (lease Lease, ok bool, err error) {
	epoch, err := s.requireSwept()
	if err != nil {
		return Lease{}, false, err
	}
	if !validTime(now) {
		return Lease{}, false, fmt.Errorf("acquire: %w", ErrInvalidTime)
	}
	err = s.inTx(ctx, "acquire", func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT j.id, j.preview_id, j.type, j.seq, j.attempts, j.repo, j.head_repo, j.pr_number,
				j.opener_login, j.opener_id, j.commit_sha, j.clone_url FROM jobs j
			WHERE j.status = 'QUEUED'
			  AND j.not_before <= ?
			  AND NOT EXISTS (SELECT 1 FROM jobs p WHERE p.preview_id = j.preview_id AND p.status = 'IN_PROGRESS')
			  AND NOT EXISTS (SELECT 1 FROM jobs q WHERE q.preview_id = j.preview_id AND q.status = 'QUEUED' AND q.seq > j.seq)
			ORDER BY j.id
			LIMIT 1`, now.UnixMilli())
		var typ string
		src := &lease.Source
		switch err := row.Scan(&lease.JobID, &lease.EnvID, &typ, &lease.Seq, &lease.Attempts, &src.Repo, &src.HeadRepo,
			&src.PRNumber, &src.OpenerLogin, &src.OpenerID, &src.CommitSHA, &src.CloneURL); {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return fmt.Errorf("acquire: select: %w", err)
		}
		lease.Type = JobType(typ)
		lease.Epoch = epoch
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'IN_PROGRESS', lease_epoch = ? WHERE id = ?`, epoch, lease.JobID); err != nil {
			return fmt.Errorf("acquire: lease job %d: %w", lease.JobID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE jobs SET status = 'SKIPPED', finished_at = ?
			WHERE preview_id = ? AND (status = 'QUEUED' OR (status = 'PENDING_APPROVAL' AND seq < ?))`,
			now.UnixMilli(), lease.EnvID, lease.Seq); err != nil {
			return fmt.Errorf("acquire: skip older jobs of %s: %w", lease.EnvID, err)
		}
		ok = true
		return nil
	})
	if err != nil {
		return Lease{}, false, err
	}
	return lease, ok, nil
}

// Finish moves a leased job to SUCCESS or FAILED at now. A teardown never
// fails (ErrTeardownCannotFail): requeue it instead.
func (s *Store) Finish(ctx context.Context, l Lease, status JobStatus, now time.Time) error {
	if status != StatusSuccess && status != StatusFailed {
		return fmt.Errorf("finish job %d: status %q is not SUCCESS or FAILED", l.JobID, status)
	}
	return s.finish(ctx, "finish", l, status, FailureNone, now)
}

// failureSteps are the failures the reconciler records: FailureNone says
// nothing, and FailureInterrupted is the sweep's own.
var failureSteps = []Failure{FailureFetch, FailurePreflight, FailureBuild, FailureStage, FailureStart,
	FailureRoute, FailureCommit, FailureUnauthorized, FailureDiskFloor}

// Fail moves a leased deploy to FAILED at now and records the step that
// failed, from the closed vocabulary (ErrInvalidFailure otherwise). A
// teardown never fails (ErrTeardownCannotFail). A disk_floor failure is a
// refusal (V1-I9): its deploy_refused audit row (previewd as actor, at now)
// is written in the same transaction.
func (s *Store) Fail(ctx context.Context, l Lease, failure Failure, now time.Time) error {
	if !slices.Contains(failureSteps, failure) {
		return fmt.Errorf("fail job %d: %w: %q", l.JobID, ErrInvalidFailure, failure)
	}
	return s.finish(ctx, "fail", l, StatusFailed, failure, now)
}

func (s *Store) finish(ctx context.Context, what string, l Lease, status JobStatus, failure Failure, now time.Time) error {
	if l.Type == JobTeardown && status == StatusFailed {
		return ErrTeardownCannotFail
	}
	if !validTime(now) {
		return fmt.Errorf("%s job %d: %w", what, l.JobID, ErrInvalidTime)
	}
	if _, err := s.requireSwept(); err != nil {
		return err
	}
	return s.inTx(ctx, what, func(tx *sql.Tx) error {
		if err := updateLease(ctx, tx, what, l,
			`UPDATE jobs SET status = ?, finished_at = ?, failure = ? WHERE id = ? AND status = 'IN_PROGRESS' AND lease_epoch = ?`,
			string(status), now.UnixMilli(), string(failure), l.JobID, l.Epoch); err != nil {
			return err
		}
		if failure != FailureDiskFloor {
			return nil
		}
		j, err := scanJob(tx.QueryRowContext(ctx, queryJobByID, l.JobID))
		if err != nil {
			return fmt.Errorf("%s job %d: read: %w", what, l.JobID, err)
		}
		src := j.Source
		return appendAudit(ctx, tx, AuditEvent{Kind: AuditDeployRefused, EnvID: j.EnvID, Repo: src.Repo,
			PRNumber: src.PRNumber, CommitSHA: src.CommitSHA, Detail: string(FailureDiskFloor)}, now)
	})
}

// Requeue puts a leased job back to QUEUED, counts the attempt and holds it
// until notBefore (backoff): a teardown after a transient failure, or a
// deploy that AuthorizeDeploy could not classify (GHES unavailable), before
// anything changed on the host. A classified deploy is never requeued
// (ErrDeployCannotRetry): it runs, or fails.
func (s *Store) Requeue(ctx context.Context, l Lease, notBefore time.Time) error {
	if _, err := s.requireSwept(); err != nil {
		return err
	}
	return s.inTx(ctx, "requeue", func(tx *sql.Tx) error {
		j, err := leasedJob(ctx, tx, "requeue", l)
		if err != nil {
			return err
		}
		if j.Type == JobDeploy && j.Trust != TrustUnclassified {
			return fmt.Errorf("requeue job %d: %w", l.JobID, ErrDeployCannotRetry)
		}
		return updateLease(ctx, tx, "requeue", l,
			`UPDATE jobs SET status = 'QUEUED', attempts = attempts + 1, not_before = ? WHERE id = ? AND status = 'IN_PROGRESS' AND lease_epoch = ?`,
			notBefore.UnixMilli(), l.JobID, l.Epoch)
	})
}

// leasedJob reads the job l holds, or fails with ErrLeaseLost.
func leasedJob(ctx context.Context, tx *sql.Tx, what string, l Lease) (Job, error) {
	j, err := scanJob(tx.QueryRowContext(ctx, queryJobByID, l.JobID))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, fmt.Errorf("%s job %d: %w", what, l.JobID, ErrLeaseLost)
	}
	if err != nil {
		return Job{}, fmt.Errorf("%s job %d: read: %w", what, l.JobID, err)
	}
	if j.Status != StatusInProgress || j.LeaseEpoch != l.Epoch {
		return Job{}, fmt.Errorf("%s job %d: %w", what, l.JobID, ErrLeaseLost)
	}
	return j, nil
}

// updateLease runs one UPDATE guarded by the lease, which must change
// exactly the leased row.
func updateLease(ctx context.Context, tx *sql.Tx, what string, l Lease, query string, args ...any) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s job %d: %w", what, l.JobID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s job %d: rows affected: %w", what, l.JobID, err)
	}
	if n != 1 {
		return fmt.Errorf("%s job %d: %w", what, l.JobID, ErrLeaseLost)
	}
	return nil
}

// StartupSweep runs once per start, before the API and the workers, with
// what the engine observes on the host. In one transaction it opens a new
// boot epoch and:
//   - keeps an environment only if it is intact and built by a SUCCESS deploy
//     whose newer jobs are all QUEUED or an interrupted teardown (D3);
//   - fails every interrupted deploy (failure = 'interrupted'), requeues
//     every interrupted teardown (D2);
//   - re-arms (QUEUED, unclassified) the latest job of an environment when it
//     is a SUCCESS deploy and the environment is not kept, e.g. after a
//     reboot wiped its staged secrets (D3). It goes through AuthorizeDeploy
//     again, so an untrusted environment comes back only on a live approval.
//
// PENDING_APPROVAL jobs are untouched. It returns every observed environment
// that exists and is not kept, including leftovers no job tracks; the caller
// destroys them before serving. Running it again on the same host state is
// idempotent.
func (s *Store) StartupSweep(ctx context.Context, now time.Time, observed []Observation) (SweepResult, error) {
	if !validTime(now) {
		return SweepResult{}, fmt.Errorf("startup sweep: %w", ErrInvalidTime)
	}
	seen := make(map[string]bool, len(observed))
	for _, o := range observed {
		if !validPreviewID(o.EnvID) || o.JobID < 0 || seen[o.EnvID] {
			return SweepResult{}, fmt.Errorf("%w: %q", ErrInvalidObservation, o.EnvID)
		}
		seen[o.EnvID] = true
	}

	var result SweepResult
	err := s.inTx(ctx, "startup sweep", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO boots (started_at) VALUES (?)`, now.UnixMilli())
		if err != nil {
			return fmt.Errorf("startup sweep: open epoch: %w", err)
		}
		if result.Epoch, err = res.LastInsertId(); err != nil {
			return fmt.Errorf("startup sweep: epoch: %w", err)
		}

		kept := map[string]bool{}
		for _, o := range observed {
			keep, err := keepEnvironment(ctx, tx, o)
			if err != nil {
				return err
			}
			switch {
			case keep:
				kept[o.EnvID] = true
			case o.exists():
				result.Destroy = append(result.Destroy, o.EnvID)
			}
		}

		// The IN_PROGRESS rewrites below neither produce nor consume a
		// SUCCESS row, so re-arming first sees the pre-sweep state.
		if err := rearm(ctx, tx, kept); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'FAILED', finished_at = ?, failure = 'interrupted' WHERE status = 'IN_PROGRESS' AND type = 'deploy'`,
			now.UnixMilli()); err != nil {
			return fmt.Errorf("startup sweep: fail interrupted deploys: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'QUEUED' WHERE status = 'IN_PROGRESS' AND type = 'teardown'`); err != nil {
			return fmt.Errorf("startup sweep: requeue interrupted teardowns: %w", err)
		}
		return nil
	})
	if err != nil {
		return SweepResult{}, err
	}
	slices.Sort(result.Destroy)
	s.epoch.Store(result.Epoch)
	return result, nil
}

// keepEnvironment is Keep(e) of the model, on the pre-sweep state.
func keepEnvironment(ctx context.Context, tx *sql.Tx, o Observation) (bool, error) {
	if !o.intact() || o.JobID == 0 {
		return false, nil
	}
	var seq int64
	err := tx.QueryRowContext(ctx, `SELECT seq FROM jobs WHERE id = ? AND preview_id = ? AND type = 'deploy' AND status = 'SUCCESS'`,
		o.JobID, o.EnvID).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("startup sweep: builder of %s: %w", o.EnvID, err)
	}
	var executedNewer int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM jobs
		WHERE preview_id = ? AND seq > ?
		  AND NOT (status = 'QUEUED' OR (status = 'IN_PROGRESS' AND type = 'teardown'))`,
		o.EnvID, seq).Scan(&executedNewer); err != nil {
		return false, fmt.Errorf("startup sweep: newer jobs of %s: %w", o.EnvID, err)
	}
	return executedNewer == 0, nil
}

// rearm queues again the latest job of every environment not kept when that
// job is a SUCCESS deploy: its environment is gone, its intent still stands,
// and its authorization is void (re-checked in this boot).
func rearm(ctx context.Context, tx *sql.Tx, kept map[string]bool) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT j.id, j.preview_id FROM jobs j
		WHERE j.type = 'deploy' AND j.status = 'SUCCESS'
		  AND NOT EXISTS (SELECT 1 FROM jobs n WHERE n.preview_id = j.preview_id AND n.seq > j.seq)`)
	if err != nil {
		return fmt.Errorf("startup sweep: re-arm candidates: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		var env string
		if err := rows.Scan(&id, &env); err != nil {
			return errors.Join(fmt.Errorf("startup sweep: scan re-arm candidate: %w", err), rows.Close())
		}
		if !kept[env] {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Join(fmt.Errorf("startup sweep: re-arm candidates: %w", err), rows.Close())
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("startup sweep: close re-arm candidates: %w", err)
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'QUEUED', not_before = 0, finished_at = 0, trust = 'unclassified' WHERE id = ?`, id); err != nil {
			return fmt.Errorf("startup sweep: re-arm job %d: %w", id, err)
		}
	}
	return nil
}

// Running returns, per environment, its latest job when that job is a
// SUCCESS deploy: the builder of a version that runs and that no newer
// intent will replace. The Revalidator checks each one (D-V1-5); an
// environment with a newer job is left to that job's AuthorizeDeploy.
func (s *Store) Running(ctx context.Context) ([]Job, error) {
	return s.listJobs(ctx, "running environments", queryRunning)
}

// RunningVersion returns the newest SUCCESS job of envID when it is a
// deploy: the builder of the version that may still run there, whatever
// newer job is queued (A2-6). It over-approximates: a deploy that failed
// since removed that version, and removing it again is harmless.
func (s *Store) RunningVersion(ctx context.Context, envID string) (Job, bool, error) {
	if !validPreviewID(envID) {
		return Job{}, false, fmt.Errorf("running version: %w: environment %s", ErrInvalidInternalJob, quoted(envID))
	}
	j, err := scanJob(s.db.QueryRowContext(ctx, queryNewestSuccess, envID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Job{}, false, nil
	case err != nil:
		return Job{}, false, fmt.Errorf("running version of %s: %w", envID, err)
	case j.Type != JobDeploy:
		return Job{}, false, nil
	}
	return j, true, nil
}

// Jobs returns every job, oldest first.
func (s *Store) Jobs(ctx context.Context) ([]Job, error) {
	return s.listJobs(ctx, "list jobs", queryAllJobs)
}

func (s *Store) listJobs(ctx context.Context, what, query string) (jobs []Job, err error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("%s: close: %w", what, closeErr))
		}
	}()
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan job: %w", what, err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return jobs, nil
}
