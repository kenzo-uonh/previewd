package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// schema3DB writes a database exactly as the shipped schema 3 leaves it, with
// the real driver, holding one approval and a short audit trail, and returns
// its path and the trail as it stands.
func schema3DB(t *testing.T) (string, []AuditRecord) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations[:3] {
		if _, err := db.ExecContext(ctx, m); err != nil {
			t.Fatalf("schema 3 migration %d: %v", i+1, err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(1_790_000_000_000)
	for i, e := range []AuditEvent{
		{Kind: AuditApprovalGranted, EnvID: envA, Repo: "acme/app", PRNumber: 1, CommitSHA: testSource.CommitSHA, ActorLogin: "lead-dev", ActorID: 7, Detail: "review"},
		{Kind: AuditUntrustedDeploy, EnvID: envA, Repo: "acme/app", PRNumber: 1, CommitSHA: testSource.CommitSHA, ActorLogin: "lead-dev", ActorID: 7, Detail: "label"},
		{Kind: AuditApprovalRevoked, EnvID: envA, Repo: "acme/app", PRNumber: 1, CommitSHA: testSource.CommitSHA, ActorLogin: "lead-dev", ActorID: 7, Detail: "dismissed"},
	} {
		if err := appendAudit(ctx, tx, e, at.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO approvals (preview_id, repo, pr_number, commit_sha, approver_login, approver_id, via, review_id, granted_seq, granted_at)
		VALUES (?, 'acme/app', 1, ?, 'lead-dev', 7, 'review', 42, 100, 1790000000000)`, envA, testSource.CommitSHA); err != nil {
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

// trail reads every audit row as stored.
func trail(t *testing.T, q querier) []AuditRecord {
	t.Helper()
	rows, err := q.QueryContext(context.Background(), queryAuditRows)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRecord
	for rows.Next() {
		var r AuditRecord
		if err := rows.Scan(&r.ID, &r.AtMillis, &r.Kind, &r.EnvID, &r.Repo, &r.PRNumber, &r.CommitSHA, &r.ActorLogin, &r.ActorID,
			&r.Detail, &r.PrevHash, &r.Hash); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Migration 4 (GitLab approvals) rebuilds approvals and audit_events to admit
// the approval path. The trail is hash-chained and append-only: every row
// keeps its bytes and its hash, the chain still verifies, and the triggers
// that make it append-only survive the rebuild.
func TestMigrateSchema3ToGitLabApprovals(t *testing.T) {
	ctx := context.Background()
	path, before := schema3DB(t)
	if len(before) != 3 {
		t.Fatalf("fixture trail has %d rows", len(before))
	}

	s, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore on a schema 3 database: %v", err)
	}
	defer func() { _ = s.Close() }()

	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != len(migrations) || version < 4 {
		t.Fatalf("user_version = %d (%v), want %d", version, err, len(migrations))
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatalf("the migrated trail does not verify: %v", err)
	}
	if after := trail(t, s.db); !slices.Equal(before, after) {
		t.Fatalf("trail changed by the migration\nbefore %+v\nafter  %+v", before, trail(t, s.db))
	}

	var login string
	var id, reviewID int64
	if err := s.db.QueryRowContext(ctx, `SELECT approver_login, approver_id, review_id FROM approvals WHERE via = 'review'`).Scan(&login, &id, &reviewID); err != nil ||
		login != "lead-dev" || id != 7 || reviewID != 42 {
		t.Fatalf("approval after migration: %q %d %d (%v)", login, id, reviewID, err)
	}

	// The new path is admitted, with no review ID, once per approver and commit.
	grant := `INSERT INTO approvals (preview_id, repo, pr_number, commit_sha, approver_login, approver_id, via, review_id, granted_seq, granted_at)
		VALUES (?, 'acme/sub/app', 1, ?, 'lead.dev', 8, 'approval', ?, 200, 1790000000001)`
	if _, err := s.db.ExecContext(ctx, grant, envA, testSource.CommitSHA, 0); err != nil {
		t.Errorf("an approval grant without a review ID refused: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, grant, envA, testSource.CommitSHA, 0); err == nil {
		t.Error("two grants of one approver, commit and path accepted")
	}
	if _, err := s.db.ExecContext(ctx, grant, envA, "2"+testSource.CommitSHA[1:], 5); err == nil {
		t.Error("an approval grant that names a review ID accepted")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE approvals SET via = 'webhook'`); err == nil {
		t.Error("a path outside the vocabulary accepted")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendAudit(ctx, tx, AuditEvent{Kind: AuditApprovalGranted, EnvID: envA, Repo: "acme/sub/app", PRNumber: 1,
		CommitSHA: testSource.CommitSHA, ActorLogin: "lead.dev", ActorID: 8, Detail: string(ApprovalViaMR)}, time.Now()); err != nil {
		t.Errorf("approval_granted via approval refused: %v", err)
	}
	if err := appendAudit(ctx, tx, AuditEvent{Kind: AuditUntrustedDeploy, EnvID: envA, Repo: "acme/sub/app", PRNumber: 1,
		CommitSHA: testSource.CommitSHA, ActorLogin: "lead.dev", ActorID: 8, Detail: string(ApprovalViaMR)}, time.Now()); err != nil {
		t.Errorf("untrusted_deploy via approval refused: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Errorf("the trail does not verify after new rows: %v", err)
	}

	for _, stmt := range []string{`UPDATE audit_events SET actor_id = 0, actor_login = ''`, `DELETE FROM audit_events`} {
		if _, err := s.db.ExecContext(ctx, stmt); err == nil {
			t.Errorf("%q accepted: the trail is no longer append-only", stmt)
		}
	}
}
