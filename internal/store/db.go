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

	return &Store{db: db}, nil
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
