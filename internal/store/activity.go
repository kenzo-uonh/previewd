package store

// HTTP ingress activity (V1.2 spec 3.3): when an environment last served a
// request, for operators deciding what sits idle. It carries no request
// data: an environment ID and an instant. The proxy's tap coalesces requests
// in memory and writes here at most once a minute per environment, so heavy
// traffic never contends for the write lock with the queue.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// upsertActivity records an instant for an environment the queue has a job
// of, never moving it back (?1 environment ID, ?2 Unix milliseconds).
const upsertActivity = `
	INSERT INTO activity (preview_id, last_active_at)
	SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM jobs WHERE preview_id = ?1)
	ON CONFLICT (preview_id) DO UPDATE SET last_active_at = max(activity.last_active_at, excluded.last_active_at)`

// UpdateLastActive records that envID served a request at lastActive. A
// later instant already recorded is kept. An environment the queue has no
// job of is ErrNoJob: nothing is recorded for a name previewd never routed,
// so the table cannot grow past the queue.
func (s *Store) UpdateLastActive(ctx context.Context, envID string, lastActive time.Time) error {
	if !validPreviewID(envID) {
		return fmt.Errorf("record activity: %w: environment %s", ErrInvalidInternalJob, quoted(envID))
	}
	if !validTime(lastActive) {
		return fmt.Errorf("record activity of %s: %w", envID, ErrInvalidTime)
	}
	res, err := s.db.ExecContext(ctx, upsertActivity, envID, lastActive.UnixMilli())
	if err != nil {
		return fmt.Errorf("record activity of %s: %w", envID, err)
	}
	n, err := res.RowsAffected()
	switch {
	case err != nil:
		return fmt.Errorf("record activity of %s: rows affected: %w", envID, err)
	case n == 0:
		return fmt.Errorf("record activity of %s: %w", envID, ErrNoJob)
	}
	return nil
}

// EnvironmentStatus is one environment as the queue and the tap know it: its
// latest job (what runs there, or what was last asked of it) and when it
// last served a request.
type EnvironmentStatus struct {
	Latest Job
	// LastActive is the latest request the tap recorded, zero when none was.
	LastActive time.Time
}

// Running reports whether the latest job built what runs there now.
func (e EnvironmentStatus) Running() bool {
	return e.Latest.Type == JobDeploy && e.Latest.Status == StatusSuccess
}

// State names what the environment is, from its latest job: running,
// deploying, awaiting-approval, failed, superseded, removing or removed.
func (e EnvironmentStatus) State() string {
	j := e.Latest
	switch {
	case j.Type == JobTeardown && j.Status == StatusSuccess:
		return "removed"
	case j.Type == JobTeardown:
		return "removing"
	case j.Status == StatusSuccess:
		return "running"
	case j.Status == StatusPendingApproval:
		return "awaiting-approval"
	case j.Status == StatusFailed:
		return "failed"
	case j.Status == StatusSkipped:
		return "superseded"
	}
	return "deploying"
}

// Queries of the status reader: the latest job of each environment and its
// activity, constant SQL, every value bound.
const (
	statusColumns = `SELECT ` + jobColumns + `,
		coalesce((SELECT a.last_active_at FROM activity a WHERE a.preview_id = j.preview_id), 0) FROM jobs j
		WHERE NOT EXISTS (SELECT 1 FROM jobs n WHERE n.preview_id = j.preview_id AND n.seq > j.seq)`
	queryStatuses = statusColumns + ` ORDER BY j.preview_id`
	queryStatus   = statusColumns + ` AND j.preview_id = ?`
)

// StatusReader reads the environments of a database file without writing to
// it (previewd list, previewd status): opened read-only and query-only,
// never migrated, at this binary's schema version only, as AuditReader.
type StatusReader struct {
	db *sql.DB
}

// OpenStatusReader opens path read-only. A database at another schema
// version is refused.
func OpenStatusReader(ctx context.Context, path string) (*StatusReader, error) {
	db, err := openReadOnly(ctx, "status", path)
	if err != nil {
		return nil, err
	}
	return &StatusReader{db: db}, nil
}

// openReadOnly opens path read-only and query-only, and refuses a database
// at another schema version or with another schema. what names the reader
// in errors.
func openReadOnly(ctx context.Context, what, path string) (*sql.DB, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("%s: database path %s is empty or contains '?' or '#'", what, quoted(path))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("%s: database path: %w", what, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String())
	if err != nil {
		return nil, fmt.Errorf("%s: open %s: %w", what, abs, err)
	}
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: read schema version of %s: %w", what, abs, err), db.Close())
	}
	if version != len(migrations) {
		return nil, errors.Join(fmt.Errorf("%s: %s is at schema version %d, this binary reads %d: start the matching daemon once to migrate it",
			what, abs, version, len(migrations)), db.Close())
	}
	if err := verifySchema(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return db, nil
}

// withActivity scans a status row: the job, then the activity instant.
type withActivity struct {
	r      rowScanner
	millis *int64
}

func (w withActivity) Scan(dest ...any) error { return w.r.Scan(append(dest, w.millis)...) }

func scanStatus(r rowScanner) (EnvironmentStatus, error) {
	var millis int64
	j, err := scanJob(withActivity{r: r, millis: &millis})
	if err != nil {
		return EnvironmentStatus{}, err
	}
	st := EnvironmentStatus{Latest: j}
	if millis > 0 {
		st.LastActive = time.UnixMilli(millis).UTC()
	}
	return st, nil
}

// Environments returns every environment the queue knows, by ID.
func (r *StatusReader) Environments(ctx context.Context) (out []EnvironmentStatus, err error) {
	rows, err := r.db.QueryContext(ctx, queryStatuses)
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("list environments: close: %w", closeErr))
		}
	}()
	for rows.Next() {
		st, err := scanStatus(rows)
		if err != nil {
			return nil, fmt.Errorf("list environments: scan: %w", err)
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	return out, nil
}

// Environment returns envID; false when the queue has no job of it.
func (r *StatusReader) Environment(ctx context.Context, envID string) (EnvironmentStatus, bool, error) {
	return environment(ctx, r.db, envID)
}

// Environment returns envID as the queue and the tap know it, for the
// status API; false when the queue has no job of it.
func (s *Store) Environment(ctx context.Context, envID string) (EnvironmentStatus, bool, error) {
	return environment(ctx, s.db, envID)
}

func environment(ctx context.Context, db *sql.DB, envID string) (EnvironmentStatus, bool, error) {
	if !validPreviewID(envID) {
		return EnvironmentStatus{}, false, fmt.Errorf("environment status: %w: environment %s", ErrInvalidInternalJob, quoted(envID))
	}
	st, err := scanStatus(db.QueryRowContext(ctx, queryStatus, envID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return EnvironmentStatus{}, false, nil
	case err != nil:
		return EnvironmentStatus{}, false, fmt.Errorf("environment status of %s: %w", envID, err)
	}
	return st, true, nil
}

// Close closes the reader.
func (r *StatusReader) Close() error { return r.db.Close() }
