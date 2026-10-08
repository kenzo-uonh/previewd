package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// maxOpenConns lets readers proceed while one writer holds the WAL write lock.
const maxOpenConns = 8

// Store encapsulates the CGO-free SQLite database operations.
type Store struct {
	db *sql.DB
	// epoch is the boot epoch recorded by StartupSweep; 0 until it runs.
	// Queue operations are refused before that.
	epoch atomic.Int64
}

// connParams applies to every pooled connection:
//   - busy_timeout: a writer waits up to 5 s for the lock instead of failing
//     with SQLITE_BUSY;
//   - _txlock=immediate: every transaction takes the write lock at BEGIN, so
//     a read-then-write transaction never has to upgrade a stale snapshot
//     (the upgrade fails with SQLITE_BUSY at once, busy_timeout or not);
//   - WAL: readers never block the writer and the writer never blocks them;
//   - synchronous=FULL: a commit survives power loss. NORMAL would be enough
//     for consistency, but a 202 acknowledges a delivery GitHub will not
//     redeliver, so the commit behind it must be durable;
//   - foreign_keys=ON.
func connParams() url.Values {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Set("_txlock", "immediate")
	return q
}

// dsn appends the connection parameters to path. The driver splits the name
// at the first '?', so a path containing one is refused rather than
// silently truncated.
func dsn(path string) (string, error) {
	if path == "" {
		return "", errors.New("database path is empty")
	}
	if strings.ContainsAny(path, "?#") {
		return "", fmt.Errorf("database path %q must not contain '?' or '#'", path)
	}
	return path + "?" + connParams().Encode(), nil
}

// NewStore opens the database at path, migrates it to the current schema
// version and verifies the schema.
func NewStore(ctx context.Context, path string) (*Store, error) {
	name, err := dsn(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", name)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		return nil, errors.Join(fmt.Errorf("database unreachable: %w", err), db.Close())
	}

	if err := migrate(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := verifySchema(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := ensureIncrementalVacuum(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}

	return &Store{db: db}, nil
}

// autoVacuumIncremental is PRAGMA auto_vacuum's value for INCREMENTAL.
const autoVacuumIncremental = 2

// ensureIncrementalVacuum converts the file to auto_vacuum = INCREMENTAL, so
// Prune can return freed pages with incremental_vacuum. SQLite applies the
// mode to a file that has tables only through a VACUUM, which cannot run in
// a transaction: it runs once, on one pinned connection, before the sweep.
// A file it cannot convert is refused.
func ensureIncrementalVacuum(ctx context.Context, db *sql.DB) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("auto_vacuum: pin connection: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("auto_vacuum: release connection: %w", closeErr))
		}
	}()
	mode, err := autoVacuumMode(ctx, conn)
	if err != nil || mode == autoVacuumIncremental {
		return err
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA auto_vacuum = INCREMENTAL`); err != nil {
		return fmt.Errorf("auto_vacuum: set incremental: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("auto_vacuum: vacuum: %w", err)
	}
	if mode, err = autoVacuumMode(ctx, conn); err != nil {
		return err
	}
	if mode != autoVacuumIncremental {
		return fmt.Errorf("auto_vacuum is %d after conversion, want %d (incremental): refusing to open", mode, autoVacuumIncremental)
	}
	return nil
}

func autoVacuumMode(ctx context.Context, conn *sql.Conn) (int, error) {
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return 0, fmt.Errorf("read auto_vacuum: %w", err)
	}
	return mode, nil
}

// migrations are forward-only. Entry i takes the schema from user_version i
// to i+1 and ends by setting that version itself (PRAGMA takes no bound
// parameter, so no statement is composed at run time); migrate checks it.
// Never edit a shipped entry: append a new one.
var migrations = []string{
	// 1: environment records. IF NOT EXISTS: databases created before
	// versioning hold this table at user_version 0. Superseded by the job
	// queue and dropped by migration 2.
	`CREATE TABLE IF NOT EXISTS environments (
		id TEXT PRIMARY KEY,
		pr_number INTEGER NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	PRAGMA user_version = 1;`,
	// 2: job queue, replay protection and boot epochs (jobs.go); the
	// environment records of migration 1 are superseded by the queue.
	`DROP TABLE IF EXISTS environments;
	CREATE TABLE jobs (
		id INTEGER PRIMARY KEY,
		preview_id TEXT NOT NULL CHECK (length(preview_id) BETWEEN 1 AND 63),
		type TEXT NOT NULL CHECK (type IN ('deploy', 'teardown')),
		seq INTEGER NOT NULL CHECK (seq > 0),
		status TEXT NOT NULL CHECK (status IN ('QUEUED', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED')),
		attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
		not_before INTEGER NOT NULL DEFAULT 0,
		lease_epoch INTEGER NOT NULL DEFAULT 0,
		repo TEXT NOT NULL CHECK (length(repo) BETWEEN 3 AND 140),
		pr_number INTEGER NOT NULL CHECK (pr_number > 0),
		commit_sha TEXT NOT NULL CHECK (length(commit_sha) IN (40, 64)),
		clone_url TEXT NOT NULL CHECK (length(clone_url) BETWEEN 1 AND 2048),
		UNIQUE (preview_id, seq),
		CHECK (type = 'teardown' OR attempts = 0),
		CHECK (type = 'deploy' OR status <> 'FAILED')
	);
	CREATE UNIQUE INDEX jobs_one_in_progress ON jobs (preview_id) WHERE status = 'IN_PROGRESS';
	CREATE INDEX jobs_by_preview ON jobs (preview_id, status, seq);
	CREATE TABLE deliveries (
		delivery_id TEXT PRIMARY KEY CHECK (length(delivery_id) BETWEEN 1 AND 64),
		payload_sha256 TEXT NOT NULL UNIQUE CHECK (length(payload_sha256) = 64),
		preview_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		verdict TEXT NOT NULL CHECK (verdict IN ('accepted', 'stale'))
	);
	CREATE TABLE boots (
		epoch INTEGER PRIMARY KEY,
		started_at INTEGER NOT NULL
	);
	PRAGMA user_version = 2;`,
	// 3: V1 (docs/specs/V1-previewd.md 3.1). SQLite cannot alter a CHECK, so
	// jobs is rebuilt: create, copy, drop, rename, index. Rows of schema 2
	// keep their values; trust is unclassified, origin webhook, created_at
	// the start of the boot that leased the job (the newest boot for a job
	// never leased; the migration time without any boot), finished_at
	// created_at for a terminal job. Their opener is unknown ('', 0) and
	// their head repository '': both are read from GHES, never trusted from
	// the row. Deliveries of schema 2 are stamped with the migration time, so
	// they age out after the retention like any other.
	//
	// approvals holds grants, revocations and heads revocations, apart: a
	// revocation can precede its grant (a new head revokes every other
	// commit, a dismissal can arrive before the approval it dismisses), and a
	// late, older grant must stay dead (V1-model.md A2-5). An approval of
	// (env, commit) is live when its newest grant is newer, by seq, than the
	// newest revocation of (env, commit) in revocations and heads.
	`CREATE TABLE jobs_v3 (
		id INTEGER PRIMARY KEY,
		preview_id TEXT NOT NULL CHECK (length(preview_id) BETWEEN 1 AND 63),
		type TEXT NOT NULL CHECK (type IN ('deploy', 'teardown')),
		origin TEXT NOT NULL DEFAULT 'webhook'
			CHECK (origin IN ('webhook', 'approval', 'revocation', 'revalidation', 'ttl')),
		seq INTEGER NOT NULL CHECK (seq > 0),
		status TEXT NOT NULL CHECK (status IN
			('PENDING_APPROVAL', 'QUEUED', 'IN_PROGRESS', 'SUCCESS', 'FAILED', 'SKIPPED')),
		trust TEXT NOT NULL DEFAULT 'unclassified' CHECK (trust IN ('unclassified', 'trusted', 'untrusted')),
		attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
		not_before INTEGER NOT NULL DEFAULT 0,
		lease_epoch INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL CHECK (created_at > 0),
		finished_at INTEGER NOT NULL DEFAULT 0 CHECK (finished_at >= 0),
		failure TEXT NOT NULL DEFAULT '' CHECK (failure IN ('', 'fetch', 'preflight', 'build', 'stage', 'start',
			'route', 'commit', 'unauthorized', 'disk_floor', 'interrupted')),
		repo TEXT NOT NULL CHECK (length(repo) BETWEEN 3 AND 140),
		head_repo TEXT NOT NULL CHECK (length(head_repo) <= 140),
		pr_number INTEGER NOT NULL CHECK (pr_number > 0),
		opener_login TEXT NOT NULL CHECK (length(opener_login) <= 39),
		opener_id INTEGER NOT NULL CHECK (opener_id >= 0),
		commit_sha TEXT NOT NULL CHECK (length(commit_sha) IN (40, 64)),
		clone_url TEXT NOT NULL CHECK (length(clone_url) BETWEEN 1 AND 2048),
		UNIQUE (preview_id, seq),
		CHECK (type = 'deploy' OR status NOT IN ('FAILED', 'PENDING_APPROVAL')),
		CHECK (type = 'deploy' OR trust = 'unclassified'),
		CHECK (type = 'teardown' OR origin IN ('webhook', 'approval')),
		CHECK (type = 'deploy' OR origin <> 'approval'),
		CHECK (status <> 'PENDING_APPROVAL' OR trust = 'unclassified'),
		CHECK ((status IN ('SUCCESS', 'FAILED', 'SKIPPED')) = (finished_at > 0)),
		CHECK (failure = '' OR status = 'FAILED'),
		CHECK ((opener_id = 0) = (opener_login = ''))
	);
	INSERT INTO jobs_v3 (id, preview_id, type, origin, seq, status, trust, attempts, not_before, lease_epoch,
		created_at, finished_at, failure, repo, head_repo, pr_number, opener_login, opener_id, commit_sha, clone_url)
	SELECT id, preview_id, type, 'webhook', seq, status, 'unclassified', attempts, not_before, lease_epoch,
		created, CASE WHEN status IN ('SUCCESS', 'FAILED', 'SKIPPED') THEN created ELSE 0 END, '',
		repo, '', pr_number, '', 0, commit_sha, clone_url
	FROM (SELECT j.*, coalesce(
			(SELECT b.started_at FROM boots b WHERE b.epoch = j.lease_epoch AND b.started_at > 0),
			(SELECT max(b.started_at) FROM boots b WHERE b.started_at > 0),
			CAST(strftime('%s', 'now') AS INTEGER) * 1000) AS created
		FROM jobs j);
	DROP TABLE jobs;
	ALTER TABLE jobs_v3 RENAME TO jobs;
	CREATE UNIQUE INDEX jobs_one_in_progress ON jobs (preview_id) WHERE status = 'IN_PROGRESS';
	CREATE INDEX jobs_by_preview ON jobs (preview_id, status, seq);
	CREATE INDEX jobs_prunable ON jobs (finished_at) WHERE finished_at > 0;

	CREATE TABLE watermarks (
		preview_id TEXT PRIMARY KEY CHECK (length(preview_id) BETWEEN 1 AND 63),
		seq INTEGER NOT NULL CHECK (seq > 0)
	);

	ALTER TABLE deliveries ADD COLUMN received_at INTEGER NOT NULL DEFAULT 0;
	UPDATE deliveries SET received_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000;
	CREATE INDEX deliveries_by_age ON deliveries (received_at);

	CREATE TABLE approvals (
		id INTEGER PRIMARY KEY,
		preview_id TEXT NOT NULL CHECK (length(preview_id) BETWEEN 1 AND 63),
		repo TEXT NOT NULL CHECK (length(repo) BETWEEN 3 AND 140),
		pr_number INTEGER NOT NULL CHECK (pr_number > 0),
		commit_sha TEXT NOT NULL CHECK (length(commit_sha) IN (40, 64)),
		approver_login TEXT NOT NULL CHECK (length(approver_login) BETWEEN 1 AND 39),
		approver_id INTEGER NOT NULL CHECK (approver_id > 0),
		via TEXT NOT NULL CHECK (via IN ('review', 'label')),
		review_id INTEGER NOT NULL DEFAULT 0 CHECK (review_id >= 0),
		granted_seq INTEGER NOT NULL CHECK (granted_seq > 0),
		granted_at INTEGER NOT NULL CHECK (granted_at > 0),
		UNIQUE (preview_id, commit_sha, approver_id, via),
		CHECK ((via = 'review') = (review_id > 0))
	);
	CREATE TABLE revocations (
		preview_id TEXT NOT NULL CHECK (length(preview_id) BETWEEN 1 AND 63),
		commit_sha TEXT NOT NULL CHECK (length(commit_sha) IN (40, 64)),
		revoked_seq INTEGER NOT NULL CHECK (revoked_seq > 0),
		revoked_at INTEGER NOT NULL CHECK (revoked_at > 0),
		reason TEXT NOT NULL CHECK (reason IN ('dismissed', 'changes_requested', 'unlabeled', 'new_head',
			'approver_removed', 'permission_lost', 'revalidation_unavailable', 'pr_closed')),
		PRIMARY KEY (preview_id, commit_sha)
	);
	CREATE TABLE heads (
		preview_id TEXT PRIMARY KEY CHECK (length(preview_id) BETWEEN 1 AND 63),
		commit_sha TEXT NOT NULL CHECK (length(commit_sha) IN (40, 64)),
		seq INTEGER NOT NULL CHECK (seq > 0),
		prior_seq INTEGER NOT NULL DEFAULT 0 CHECK (prior_seq >= 0 AND prior_seq < seq)
	);

	CREATE TABLE audit_events (
		id INTEGER PRIMARY KEY CHECK (id > 0),
		at INTEGER NOT NULL CHECK (at > 0),
		kind TEXT NOT NULL CHECK (kind IN ('trusted_deploy', 'untrusted_deploy', 'approval_granted',
			'approval_revoked', 'deploy_refused', 'teardown', 'ttl_expired', 'full_secrets_opt_in')),
		preview_id TEXT NOT NULL CHECK (length(preview_id) BETWEEN 1 AND 63),
		repo TEXT NOT NULL CHECK (length(repo) BETWEEN 3 AND 140),
		pr_number INTEGER NOT NULL CHECK (pr_number > 0),
		commit_sha TEXT NOT NULL CHECK (length(commit_sha) IN (0, 40, 64)),
		actor_login TEXT NOT NULL CHECK (length(actor_login) <= 39),
		actor_id INTEGER NOT NULL CHECK (actor_id >= 0),
		detail TEXT NOT NULL CHECK (detail IN ('write_access', 'review', 'label', 'dismissed',
			'changes_requested', 'unlabeled', 'new_head', 'approver_removed', 'permission_lost',
			'revalidation_unavailable', 'pr_closed', 'not_approved', 'disk_floor', 'webhook', 'revocation',
			'revalidation', 'ttl', 'opt_in')),
		prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64),
		hash TEXT NOT NULL UNIQUE CHECK (length(hash) = 64),
		CHECK ((actor_id = 0) = (actor_login = ''))
	);
	CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
		BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
	CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
		BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
	PRAGMA user_version = 3;`,
}

// migrate applies every migration above the database's user_version, each in
// its own transaction together with its version bump. A database newer than
// this binary, or a migration that does not set its version, is refused.
func migrate(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("schema version %d is newer than this binary (%d): refusing to open", version, len(migrations))
	}
	for v := version; v < len(migrations); v++ {
		if err := applyMigration(ctx, db, v); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, from int) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", from+1, err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback migration %d: %w", from+1, rbErr))
			}
		}
	}()
	if _, err := tx.ExecContext(ctx, migrations[from]); err != nil {
		return fmt.Errorf("apply migration %d: %w", from+1, err)
	}
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version after migration %d: %w", from+1, err)
	}
	if version != from+1 {
		return fmt.Errorf("migration %d left schema version %d", from+1, version)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", from+1, err)
	}
	return nil
}

// Close safely terminates the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
