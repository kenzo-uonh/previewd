package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

// schema4DB writes a database exactly as the shipped schema 4 leaves it, with
// the real driver: one job and a short audit trail.
func schema4DB(t *testing.T) (string, []AuditRecord) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations[:4] {
		if _, err := db.ExecContext(ctx, m); err != nil {
			t.Fatalf("schema 4 migration %d: %v", i+1, err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendAudit(ctx, tx, AuditEvent{Kind: AuditTrustedDeploy, EnvID: envA, Repo: "acme/app", PRNumber: 7,
		CommitSHA: testSource.CommitSHA, ActorLogin: "opener", ActorID: 4242, Detail: auditDetailWriteAccess}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO jobs (preview_id, type, origin, seq, status, trust, created_at, finished_at, repo, head_repo, pr_number,
			opener_login, opener_id, commit_sha, clone_url)
		VALUES (?, 'deploy', 'webhook', 100, 'SUCCESS', 'trusted', 1790000000000, 1790000000001, 'acme/app', 'acme/app', 7,
			'opener', 4242, ?, 'https://git.example.internal/acme/app.git')`, envA, testSource.CommitSHA); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	records := trail(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path, records
}

// Migration 5 (ingress activity) only adds a table: every row of schema 4
// is kept, the trail verifies, and the new table enforces its bounds.
func TestMigrateSchema4ToActivity(t *testing.T) {
	ctx := context.Background()
	path, before := schema4DB(t)

	s, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore on a schema 4 database: %v", err)
	}
	defer func() { _ = s.Close() }()

	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != len(migrations) || version < 5 {
		t.Fatalf("user_version = %d (%v), want %d", version, err, len(migrations))
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatalf("the migrated trail does not verify: %v", err)
	}
	if after := trail(t, s.db); !slices.Equal(before, after) {
		t.Fatalf("trail changed by the migration")
	}
	jobs, err := s.Jobs(ctx)
	if err != nil || len(jobs) != 1 || jobs[0].EnvID != envA || jobs[0].Status != StatusSuccess {
		t.Fatalf("jobs after migration: %+v, %v", jobs, err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM activity`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("activity rows after migration: %d, %v", n, err)
	}
	var index string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'activity' AND name = 'activity_by_last_active'`).Scan(&index); err != nil {
		t.Errorf("the last_active_at index is missing: %v", err)
	}

	if err := s.UpdateLastActive(ctx, envA, t0); err != nil {
		t.Fatalf("activity of a migrated environment: %v", err)
	}
	for name, stmt := range map[string]string{
		"zero instant":   `INSERT INTO activity (preview_id, last_active_at) VALUES ('pr-9-x', 0)`,
		"empty id":       `INSERT INTO activity (preview_id, last_active_at) VALUES ('', 1)`,
		"long id":        `INSERT INTO activity (preview_id, last_active_at) VALUES ('` + string(make([]byte, 64)) + `', 1)`,
		"second row":     `INSERT INTO activity (preview_id, last_active_at) VALUES ('` + envA + `', 2)`,
		"no instant":     `INSERT INTO activity (preview_id) VALUES ('pr-9-y')`,
		"text as millis": `INSERT INTO activity (preview_id, last_active_at) VALUES ('pr-9-z', NULL)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The read-only readers open the migrated file; they refuse schema 4.
	r, err := OpenStatusReader(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	old, _ := schema4DB(t)
	if _, err := OpenStatusReader(ctx, old); err == nil {
		t.Error("the status reader opened a schema 4 database")
	}
	if _, err := OpenAuditReader(ctx, old); err == nil {
		t.Error("the audit reader opened a schema 4 database")
	}
}
