package store

// The durable job queue: the SQLite implementation of db_jobs in
// docs/formal/previewd.tla. Each exported operation is one IMMEDIATE
// transaction and implements one transition of the model:
//
//	Enqueue       ReceiveWebhook (replay protection by delivery ID and by
//	              payload, D1 stale rule)
//	Acquire       AcquireJob (newest intent wins, older ones SKIPPED)
//	Finish        CommitDeploy, CommitTeardown, deploy failure rollback
//	Requeue       ExecuteTeardown transient failure (never FAILED)
//	StartupSweep  StartupSweep (D2, D3)
//
// The per-environment lock is the IN_PROGRESS row itself, enforced by the
// partial unique index jobs_one_in_progress. A lease carries the boot epoch
// it was taken in; any operation on a lease from an earlier boot, or on a
// job the sweep already rewrote, fails with ErrLeaseLost and changes nothing.

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
const (
	StatusQueued     JobStatus = "QUEUED"
	StatusInProgress JobStatus = "IN_PROGRESS"
	StatusSuccess    JobStatus = "SUCCESS"
	StatusFailed     JobStatus = "FAILED"
	StatusSkipped    JobStatus = "SKIPPED"
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
	ErrTeardownCannotFail = errors.New("a teardown never fails: requeue it")
	ErrDeployCannotRetry  = errors.New("a deploy is never requeued: finish it as FAILED")
)

const (
	maxPreviewIDLen  = 63
	maxDeliveryIDLen = 64
	maxRepoLen       = 140
	maxCloneURLLen   = 2048
)

// Source is what a deploy needs to build the environment. The API validates
// it (internal/validate) before it reaches the queue; the store only bounds
// it.
type Source struct {
	Repo      string
	PRNumber  int64
	CommitSHA string
	CloneURL  string
}

// Delivery is one signed webhook delivery. ID is the delivery GUID and
// PayloadSHA256 the hex SHA-256 of the signed body: both are replay keys,
// the second because GitHub does not sign the delivery header, so a captured
// body resent under a new ID is still a replay. Seq orders intents of the
// same environment: a delivery whose Seq is not above every job already
// recorded for EnvID is stale.
type Delivery struct {
	ID            string
	PayloadSHA256 string
	EnvID         string
	Type          JobType
	Seq           int64
	Source        Source
}

// Job is one row of the queue.
type Job struct {
	ID         int64
	EnvID      string
	Type       JobType
	Seq        int64
	Status     JobStatus
	Attempts   int64
	NotBefore  int64 // Unix milliseconds; Acquire skips the job before then
	LeaseEpoch int64
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

func isLowerHex(s string) bool {
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (d Delivery) valid() bool {
	src := d.Source
	return d.ID != "" && len(d.ID) <= maxDeliveryIDLen &&
		len(d.PayloadSHA256) == 64 && isLowerHex(d.PayloadSHA256) &&
		validPreviewID(d.EnvID) && validType(d.Type) && d.Seq > 0 &&
		len(src.Repo) >= 3 && len(src.Repo) <= maxRepoLen && src.PRNumber > 0 &&
		(len(src.CommitSHA) == 40 || len(src.CommitSHA) == 64) && isLowerHex(src.CommitSHA) &&
		src.CloneURL != "" && len(src.CloneURL) <= maxCloneURLLen
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

// Enqueue records a delivery. A delivery whose ID or payload was already seen
// is a replay and changes nothing. A delivery is stale when any job of the
// same environment has a Seq at or above it, whatever that job's status
// (D1): a newer intent that failed or was skipped still supersedes it.
// Otherwise a QUEUED job is appended and its ID returned.
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
		var seen int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deliveries WHERE delivery_id = ? OR payload_sha256 = ?`, d.ID, d.PayloadSHA256).Scan(&seen); err != nil {
			return fmt.Errorf("enqueue: replay check: %w", err)
		}
		if seen > 0 {
			verdict = VerdictReplay
			return nil
		}
		var newer int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE preview_id = ? AND seq >= ?`, d.EnvID, d.Seq).Scan(&newer); err != nil {
			return fmt.Errorf("enqueue: order check: %w", err)
		}
		verdict = VerdictAccepted
		if newer > 0 {
			verdict = VerdictStale
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries (delivery_id, payload_sha256, preview_id, seq, verdict) VALUES (?, ?, ?, ?, ?)`,
			d.ID, d.PayloadSHA256, d.EnvID, d.Seq, string(verdict)); err != nil {
			return fmt.Errorf("enqueue: record delivery: %w", err)
		}
		if verdict == VerdictStale {
			return nil
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO jobs (preview_id, type, seq, status, repo, pr_number, commit_sha, clone_url)
			VALUES (?, ?, ?, 'QUEUED', ?, ?, ?, ?)`,
			d.EnvID, string(d.Type), d.Seq, d.Source.Repo, d.Source.PRNumber, d.Source.CommitSHA, d.Source.CloneURL)
		if err != nil {
			return fmt.Errorf("enqueue: insert job: %w", err)
		}
		if jobID, err = res.LastInsertId(); err != nil {
			return fmt.Errorf("enqueue: job id: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return verdict, jobID, nil
}

// Acquire leases the next job. An environment is ready when it has no
// IN_PROGRESS job and its newest QUEUED job is due at now. Among ready
// environments, the one whose newest QUEUED job has the lowest ID goes
// first. In the same transaction the newest QUEUED job becomes IN_PROGRESS
// and every older QUEUED job of that environment becomes SKIPPED. ok is
// false when nothing is ready.
func (s *Store) Acquire(ctx context.Context, now time.Time) (lease Lease, ok bool, err error) {
	epoch, err := s.requireSwept()
	if err != nil {
		return Lease{}, false, err
	}
	err = s.inTx(ctx, "acquire", func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT j.id, j.preview_id, j.type, j.seq, j.attempts, j.repo, j.pr_number, j.commit_sha, j.clone_url FROM jobs j
			WHERE j.status = 'QUEUED'
			  AND j.not_before <= ?
			  AND NOT EXISTS (SELECT 1 FROM jobs p WHERE p.preview_id = j.preview_id AND p.status = 'IN_PROGRESS')
			  AND NOT EXISTS (SELECT 1 FROM jobs q WHERE q.preview_id = j.preview_id AND q.status = 'QUEUED' AND q.seq > j.seq)
			ORDER BY j.id
			LIMIT 1`, now.UnixMilli())
		var typ string
		src := &lease.Source
		switch err := row.Scan(&lease.JobID, &lease.EnvID, &typ, &lease.Seq, &lease.Attempts, &src.Repo, &src.PRNumber, &src.CommitSHA, &src.CloneURL); {
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
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'SKIPPED' WHERE preview_id = ? AND status = 'QUEUED'`, lease.EnvID); err != nil {
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

// Finish moves a leased job to SUCCESS or FAILED. A teardown never fails
// (ErrTeardownCannotFail): requeue it instead.
func (s *Store) Finish(ctx context.Context, l Lease, status JobStatus) error {
	if status != StatusSuccess && status != StatusFailed {
		return fmt.Errorf("finish job %d: status %q is not SUCCESS or FAILED", l.JobID, status)
	}
	if l.Type == JobTeardown && status == StatusFailed {
		return ErrTeardownCannotFail
	}
	return s.updateLease(ctx, "finish", l, `UPDATE jobs SET status = ? WHERE id = ? AND status = 'IN_PROGRESS' AND lease_epoch = ?`,
		string(status), l.JobID, l.Epoch)
}

// Requeue puts a leased teardown back to QUEUED after a transient failure,
// counts the attempt and holds it until notBefore (backoff).
func (s *Store) Requeue(ctx context.Context, l Lease, notBefore time.Time) error {
	if l.Type != JobTeardown {
		return ErrDeployCannotRetry
	}
	return s.updateLease(ctx, "requeue",
		l, `UPDATE jobs SET status = 'QUEUED', attempts = attempts + 1, not_before = ? WHERE id = ? AND status = 'IN_PROGRESS' AND lease_epoch = ?`,
		notBefore.UnixMilli(), l.JobID, l.Epoch)
}

func (s *Store) updateLease(ctx context.Context, what string, l Lease, query string, args ...any) error {
	if _, err := s.requireSwept(); err != nil {
		return err
	}
	return s.inTx(ctx, what, func(tx *sql.Tx) error {
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
	})
}

// StartupSweep runs once per start, before the API and the workers, with
// what the engine observes on the host. In one transaction it opens a new
// boot epoch and:
//   - keeps an environment only if it is intact and built by a SUCCESS deploy
//     whose newer jobs are all QUEUED or an interrupted teardown (D3);
//   - fails every interrupted deploy, requeues every interrupted teardown (D2);
//   - re-arms (QUEUED) the latest job of an environment when it is a SUCCESS
//     deploy and the environment is not kept, e.g. after a reboot wiped its
//     staged secrets (D3).
//
// It returns every observed environment that exists and is not kept,
// including leftovers no job tracks; the caller destroys them before serving.
// Running it again on the same host state is idempotent.
func (s *Store) StartupSweep(ctx context.Context, now time.Time, observed []Observation) (SweepResult, error) {
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
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'FAILED' WHERE status = 'IN_PROGRESS' AND type = 'deploy'`); err != nil {
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
// job is a SUCCESS deploy: its environment is gone, its intent still stands.
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
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'QUEUED', not_before = 0 WHERE id = ?`, id); err != nil {
			return fmt.Errorf("startup sweep: re-arm job %d: %w", id, err)
		}
	}
	return nil
}

// Jobs returns every job, oldest first.
func (s *Store) Jobs(ctx context.Context) (jobs []Job, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, preview_id, type, seq, status, attempts, not_before, lease_epoch, repo, pr_number, commit_sha, clone_url
		FROM jobs ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close job list: %w", closeErr))
		}
	}()
	for rows.Next() {
		var j Job
		var typ, status string
		src := &j.Source
		if err := rows.Scan(&j.ID, &j.EnvID, &typ, &j.Seq, &status, &j.Attempts, &j.NotBefore, &j.LeaseEpoch,
			&src.Repo, &src.PRNumber, &src.CommitSHA, &src.CloneURL); err != nil {
			return nil, fmt.Errorf("scan job: %w", err)
		}
		j.Type, j.Status = JobType(typ), JobStatus(status)
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	return jobs, nil
}
