package store

// Bounded storage (F3) and expiry (F5): the model's Prune and Expire.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// keptBoots is the number of newest boot epochs Prune keeps.
	keptBoots = 100
	// deliveryReplayMargin is added to PREVIEWD_DELIVERY_MAX_AGE: a delivery
	// is kept at least as long as its signed time can still pass V1-I7.
	deliveryReplayMargin = 5 * time.Minute
)

// ErrInvalidPrune rejects a malformed PruneRequest.
var ErrInvalidPrune = errors.New("invalid prune request")

// PruneRequest is one Prune pass. Builders are the builder job IDs of every
// environment that exists on the host (ownership labels): the sweep and
// Safety 2 read them, so they are never pruned (V1-model.md A1-6).
type PruneRequest struct {
	Now            time.Time
	Retention      time.Duration // PREVIEWD_RETENTION (config enforces >= 24h)
	DeliveryMaxAge time.Duration // PREVIEWD_DELIVERY_MAX_AGE
	Batch          int           // PREVIEWD_PRUNE_BATCH: rows per transaction
	Builders       []int64
}

// PruneStats counts what one Prune deleted.
type PruneStats struct {
	Jobs       int64
	Deliveries int64
	Approvals  int64
	Boots      int64
}

func (r PruneRequest) valid() bool {
	if !validTime(r.Now) || r.Retention < 0 || r.DeliveryMaxAge < 0 || r.Batch < 1 {
		return false
	}
	for _, id := range r.Builders {
		if id <= 0 {
			return false
		}
	}
	return true
}

// Prune deletes, in transactions of at most req.Batch rows:
//   - jobs: terminal, finished before Now - Retention, neither the
//     highest-seq job of their environment nor a builder of what exists.
//     The environment's watermark is raised to their seq first, in the same
//     transaction, so the stale rule's verdicts do not change (V1-I6);
//   - deliveries: received before Now - max(Retention, DeliveryMaxAge + 5 min)
//     and at or below MaxSeq of their environment (a replay of one is stale);
//   - approvals: grants granted before Now - Retention that are no longer
//     live. A newer grant revives nothing of them, and revocations,
//     watermarks and heads are never deleted, so a late, older grant stays
//     dead;
//   - boots: all but the newest 100.
//
// Non-terminal jobs, the latest job of an environment and audit rows are
// never deleted. It then returns up to 1,000 free pages to the file system
// (incremental_vacuum).
func (s *Store) Prune(ctx context.Context, req PruneRequest) (PruneStats, error) {
	var stats PruneStats
	if _, err := s.requireSwept(); err != nil {
		return stats, err
	}
	if !req.valid() {
		return stats, ErrInvalidPrune
	}
	builders, err := json.Marshal(append([]int64{}, req.Builders...))
	if err != nil {
		return stats, fmt.Errorf("prune: encode builders: %w", err)
	}
	jobCutoff := req.Now.Add(-req.Retention).UnixMilli()
	deliveryCutoff := req.Now.Add(-max(req.Retention, req.DeliveryMaxAge+deliveryReplayMargin)).UnixMilli()

	if stats.Jobs, err = s.pruneBatches(ctx, "prune jobs", req.Batch, func(tx *sql.Tx) (int64, error) {
		return pruneJobs(ctx, tx, jobCutoff, string(builders), req.Batch)
	}); err != nil {
		return stats, err
	}
	if stats.Deliveries, err = s.pruneBatches(ctx, "prune deliveries", req.Batch, func(tx *sql.Tx) (int64, error) {
		return execCount(ctx, tx, "prune deliveries", `
			DELETE FROM deliveries WHERE delivery_id IN (
				SELECT d.delivery_id FROM deliveries d
				WHERE d.received_at < ?
				  AND d.seq <= max(
					coalesce((SELECT max(j.seq) FROM jobs j WHERE j.preview_id = d.preview_id), 0),
					coalesce((SELECT w.seq FROM watermarks w WHERE w.preview_id = d.preview_id), 0))
				LIMIT ?)`, deliveryCutoff, req.Batch)
	}); err != nil {
		return stats, err
	}
	if stats.Approvals, err = s.pruneBatches(ctx, "prune approvals", req.Batch, func(tx *sql.Tx) (int64, error) {
		return execCount(ctx, tx, "prune approvals", `
			DELETE FROM approvals WHERE id IN (
				SELECT a.id FROM approvals a
				WHERE a.granted_at < ?
				  AND a.granted_seq <= max(
					coalesce((SELECT r.revoked_seq FROM revocations r WHERE r.preview_id = a.preview_id AND r.commit_sha = a.commit_sha), 0),
					coalesce((SELECT CASE WHEN h.commit_sha = a.commit_sha THEN h.prior_seq ELSE h.seq END FROM heads h WHERE h.preview_id = a.preview_id), 0))
				LIMIT ?)`, jobCutoff, req.Batch)
	}); err != nil {
		return stats, err
	}
	if err := s.inTx(ctx, "prune boots", func(tx *sql.Tx) error {
		stats.Boots, err = execCount(ctx, tx, "prune boots",
			`DELETE FROM boots WHERE epoch <= (SELECT max(epoch) FROM boots) - ?`, keptBoots)
		return err
	}); err != nil {
		return stats, err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(1000)`); err != nil {
		return stats, fmt.Errorf("prune: incremental vacuum: %w", err)
	}
	return stats, nil
}

// pruneBatches runs one batch per transaction until a batch deletes fewer
// rows than the limit, and returns the total.
func (s *Store) pruneBatches(ctx context.Context, what string, batch int, fn func(*sql.Tx) (int64, error)) (int64, error) {
	var total int64
	for {
		var n int64
		if err := s.inTx(ctx, what, func(tx *sql.Tx) error {
			var err error
			n, err = fn(tx)
			return err
		}); err != nil {
			return total, err
		}
		total += n
		if n < int64(batch) {
			return total, nil
		}
	}
}

// Prune queries for jobs: constant SQL, every value bound (?1 cutoff, ?2
// builder IDs as a JSON array, ?3 batch).
const (
	prunableJobs = `
		SELECT j.id FROM jobs j
		WHERE j.status IN ('SUCCESS', 'FAILED', 'SKIPPED')
		  AND j.finished_at > 0 AND j.finished_at < ?1
		  AND j.id NOT IN (SELECT value FROM json_each(?2))
		  AND EXISTS (SELECT 1 FROM jobs n WHERE n.preview_id = j.preview_id AND n.seq > j.seq)
		ORDER BY j.id
		LIMIT ?3`
	raiseWatermarks = `
		INSERT INTO watermarks (preview_id, seq)
		SELECT p.preview_id, max(p.seq) FROM jobs p WHERE p.id IN (` + prunableJobs + `) GROUP BY p.preview_id
		ON CONFLICT (preview_id) DO UPDATE SET seq = max(watermarks.seq, excluded.seq)`
	deletePrunableJobs = `DELETE FROM jobs WHERE id IN (` + prunableJobs + `)`
)

// pruneJobs deletes up to batch prunable jobs after raising the watermark of
// their environments to their seq.
func pruneJobs(ctx context.Context, tx *sql.Tx, cutoff int64, builders string, batch int) (int64, error) {
	if _, err := tx.ExecContext(ctx, raiseWatermarks, cutoff, builders, batch); err != nil {
		return 0, fmt.Errorf("prune jobs: raise watermarks: %w", err)
	}
	return execCount(ctx, tx, "prune jobs", deletePrunableJobs, cutoff, builders, batch)
}

func execCount(ctx context.Context, tx *sql.Tx, what, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", what, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%s: rows affected: %w", what, err)
	}
	return n, nil
}

// Expired returns, sorted, the environments whose latest job is a SUCCESS
// deploy finished at or before now - ttl: what runs is older than its TTL
// and nothing newer is recorded. The Expirer queues their teardown
// (EnqueueInternal, origin ttl); a later push deploys again.
func (s *Store) Expired(ctx context.Context, ttl time.Duration, now time.Time) (envs []string, err error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("expired: ttl %s is not positive", ttl)
	}
	if !validTime(now) {
		return nil, fmt.Errorf("expired: %w", ErrInvalidTime)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT j.preview_id FROM jobs j
		WHERE j.type = 'deploy' AND j.status = 'SUCCESS' AND j.finished_at <= ?
		  AND NOT EXISTS (SELECT 1 FROM jobs n WHERE n.preview_id = j.preview_id AND n.seq > j.seq)
		ORDER BY j.preview_id`, now.Add(-ttl).UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("expired: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("expired: close: %w", closeErr))
		}
	}()
	for rows.Next() {
		var env string
		if err := rows.Scan(&env); err != nil {
			return nil, fmt.Errorf("expired: scan: %w", err)
		}
		envs = append(envs, env)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("expired: %w", err)
	}
	return envs, nil
}
