package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "previewd.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

// The shipped schema passes, through the real constructor on the real
// modernc driver.
func TestNewStoreAcceptsShippedSchema(t *testing.T) {
	s, err := NewStore(context.Background(), filepath.Join(t.TempDir(), "previewd.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// Fail closed: any drift a migration could introduce refuses the database.
func TestVerifySchemaRefusesDrift(t *testing.T) {
	for name, ddl := range map[string]string{
		"secret text column":         `ALTER TABLE jobs ADD COLUMN token TEXT`,
		"innocent text column":       `ALTER TABLE deliveries ADD COLUMN note TEXT`,
		"blob column":                `ALTER TABLE jobs ADD COLUMN payload BLOB`,
		"untyped column":             `ALTER TABLE boots ADD COLUMN extra`,
		"varchar column":             `ALTER TABLE jobs ADD COLUMN env VARCHAR(255)`,
		"new table":                  `CREATE TABLE leases (id INTEGER PRIMARY KEY)`,
		"new table with blob":        `CREATE TABLE cache (k INTEGER, v BLOB)`,
		"allowlisted column retyped": `ALTER TABLE jobs RENAME COLUMN clone_url TO clone_url_old; ALTER TABLE jobs ADD COLUMN clone_url BLOB`,
		"old environments table":     `CREATE TABLE environments (id TEXT PRIMARY KEY, pr_number INTEGER NOT NULL, status TEXT NOT NULL)`,
		"allowlisted column missing": `ALTER TABLE deliveries DROP COLUMN verdict`,
		"allowlisted table missing":  `DROP TABLE boots`,
	} {
		t.Run(name, func(t *testing.T) {
			db := openTestDB(t)
			if _, err := db.ExecContext(context.Background(), ddl); err != nil {
				t.Fatal(err)
			}
			if err := verifySchema(context.Background(), db); err == nil {
				t.Fatalf("schema accepted after %q", ddl)
			}
		})
	}
}

// The allowlist itself never admits a BLOB-affinity column or a column whose
// name suggests secret material.
func TestSchemaAllowlistIsSecretFree(t *testing.T) {
	secretish := regexp.MustCompile(`(?i)secret|token|passw|cred|key|auth|env$|^env|cert|private`)
	for table, cols := range schemaAllowlist {
		for col, declType := range cols {
			if blobAffinity(declType) {
				t.Errorf("%s.%s allowlisted with BLOB affinity %q", table, col, declType)
			}
			if secretish.MatchString(col) {
				t.Errorf("%s.%s allowlisted with a secret-like name", table, col)
			}
		}
	}
}

func TestBlobAffinity(t *testing.T) {
	for declType, want := range map[string]bool{
		"": true, "BLOB": true, "blob": true, "MEDIUMBLOB": true,
		"TEXT": false, "VARCHAR(10)": false, "CLOB": false, "INTEGER": false, "BIGINT": false,
		"DATETIME": false, "REAL": false, "NUMERIC": false,
		// "INT" wins over "BLOB" in SQLite's rule order.
		"INTBLOB": false,
	} {
		if got := blobAffinity(declType); got != want {
			t.Errorf("blobAffinity(%q) = %v, want %v", declType, got, want)
		}
	}
}

// Wiring: the daemon refuses to start on a drifted database file.
func TestNewStoreRefusesDriftedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `ALTER TABLE jobs ADD COLUMN token TEXT`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if s, err := NewStore(context.Background(), path); err == nil {
		_ = s.Close()
		t.Fatal("NewStore opened a database with a non-allowlisted TEXT column")
	}
}

// A schema-version-2 database from before the jobs carried their source
// (commit 8ec4c66, unreleased) is refused at start, not at the first query.
func TestNewStoreRefusesEarlierVersion2Schema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ddl := range []string{
		`CREATE TABLE jobs (id INTEGER PRIMARY KEY, preview_id TEXT NOT NULL, type TEXT NOT NULL, seq INTEGER NOT NULL,
			status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, not_before INTEGER NOT NULL DEFAULT 0,
			lease_epoch INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE deliveries (delivery_id TEXT PRIMARY KEY, preview_id TEXT NOT NULL, seq INTEGER NOT NULL, verdict TEXT NOT NULL)`,
		`CREATE TABLE boots (epoch INTEGER PRIMARY KEY, started_at INTEGER NOT NULL)`,
		`PRAGMA user_version = 2`,
	} {
		if _, err := db.ExecContext(context.Background(), ddl); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := NewStore(context.Background(), path); err == nil {
		_ = s.Close()
		t.Fatal("NewStore opened a version-2 database without the job source columns")
	}
}

// v2FixtureDB is the schema-2 fixture (make store-fixture-v2,
// fixture_gen_test.go): one row for every job state schema 2 could hold.
const v2FixtureDB = "testdata/schema-v2-modernc.sqlite"

// copyFixture copies a committed fixture into a temporary directory.
func copyFixture(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s (make store-fixture-v2): %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), "previewd.sqlite")
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

// Migration 3 on a database schema 2 wrote, through the real driver:
// every job kept, value for value, with the V1 defaults; created_at from
// the boot that leased the job (the newest boot otherwise); deliveries
// stamped with the migration time; the result passes verifySchema and is
// converted to incremental auto_vacuum.
func TestMigrateSchemaV2Fixture(t *testing.T) {
	ctx := context.Background()
	path := copyFixture(t, v2FixtureDB)
	before := time.Now()
	s := openStore(t, path)
	after := time.Now()

	var version, autoVacuum int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("user_version = %d (%v), want %d", version, err, len(migrations))
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil || autoVacuum != autoVacuumIncremental {
		t.Fatalf("auto_vacuum = %d (%v), want incremental", autoVacuum, err)
	}

	const boot1, boot2 = 1790000000000, 1790000600000
	src := func(pr int64, repo, commit string) Source {
		return Source{Repo: repo, PRNumber: pr, CommitSHA: commit, CloneURL: "https://git.example.internal/" + repo + ".git"}
	}
	a := src(1, "acme/app", strings.Repeat("1", 40))
	job := func(id int64, env string, typ JobType, seq int64, st JobStatus, attempts, notBefore, epoch, created int64, s Source) Job {
		j := Job{ID: id, EnvID: env, Type: typ, Origin: OriginWebhook, Seq: seq, Status: st, Trust: TrustUnclassified,
			Attempts: attempts, NotBefore: notBefore, LeaseEpoch: epoch, CreatedAt: created, Source: s}
		if st == StatusSuccess || st == StatusFailed || st == StatusSkipped {
			j.FinishedAt = created
		}
		return j
	}
	want := []Job{
		job(1, "pr-1-0a0a0a0a0a", JobDeploy, 100, StatusSuccess, 0, 0, 1, boot1, a),
		job(2, "pr-1-0a0a0a0a0a", JobTeardown, 200, StatusQueued, 2, 1790000700000, 2, boot2, a),
		job(3, "pr-2-0b0b0b0b0b", JobDeploy, 150, StatusSkipped, 0, 0, 0, boot2, src(2, "acme/app", strings.Repeat("2", 40))),
		job(4, "pr-2-0b0b0b0b0b", JobDeploy, 160, StatusFailed, 0, 0, 1, boot1, src(2, "acme/app", strings.Repeat("3", 40))),
		job(5, "pr-2-0b0b0b0b0b", JobDeploy, 170, StatusInProgress, 0, 0, 2, boot2, src(2, "acme/app", strings.Repeat("4", 40))),
		job(6, "pr-3-0c0c0c0c0c", JobDeploy, 300, StatusQueued, 0, 0, 0, boot2, src(3, "acme/sha256", strings.Repeat("5", 64))),
	}
	got, err := s.Jobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("migrated jobs\n got:  %+v\n want: %+v", got, want)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT delivery_id, received_at FROM deliveries ORDER BY delivery_id`)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		var at int64
		if err := rows.Scan(&id, &at); err != nil {
			t.Fatal(err)
		}
		if at < before.Unix()*1000 || at > after.UnixMilli() {
			t.Errorf("delivery %s received_at %d, want the migration time [%d, %d]", id, at, before.Unix()*1000, after.UnixMilli())
		}
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []string{"d-1", "d-2", "d-3", "d-4"}) {
		t.Fatalf("deliveries %v, want all four", ids)
	}

	// The migrated queue works: the sweep fails the interrupted deploy, the
	// stale rule still reads the migrated seqs.
	if _, err := s.StartupSweep(ctx, after, nil); err != nil {
		t.Fatal(err)
	}
	if jobs, err := s.Jobs(ctx); err != nil || jobs[4].Status != StatusFailed || jobs[4].Failure != FailureInterrupted {
		t.Fatalf("interrupted migrated deploy = %+v (%v), want FAILED, interrupted", jobs[4], err)
	}
	d := testDelivery("d-5", "pr-1-0a0a0a0a0a", JobDeploy, 200)
	if v, _, err := s.Enqueue(ctx, d); err != nil || v != VerdictStale {
		t.Fatalf("delivery at a migrated seq = %s (%v), want stale", v, err)
	}
}

// A legacy job's unknown opener is the only empty one SQLite accepts: a
// login without an ID, or an ID without a login, is refused.
func TestSchemaOpenerKnownOrUnknown(t *testing.T) {
	s, _ := sweptStore(t)
	enqueue(t, s, "d1", envA, JobDeploy, 1)
	ctx := context.Background()
	for _, stmt := range []string{
		`UPDATE jobs SET opener_login = ''`,
		`UPDATE jobs SET opener_id = 0`,
		`UPDATE jobs SET opener_login = '', opener_id = 7`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err == nil {
			t.Errorf("%s accepted", stmt)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE jobs SET opener_login = '', opener_id = 0`); err != nil {
		t.Errorf("unknown opener refused: %v", err)
	}
}

// B2: audit_events is append-only in SQLite itself.
func TestAuditEventsAppendOnly(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	if err := s.AppendAudit(ctx, testAuditEvent(AuditFullSecretsOptIn, "opt_in"), t0); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE audit_events SET detail = 'opt_in'`,
		`UPDATE audit_events SET hash = prev_hash`,
		`DELETE FROM audit_events`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: %v, want the append-only abort", stmt, err)
		}
	}
	if err := s.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

// B2: every closed vocabulary of schema 3 accepts each Go constant and
// refuses a value outside it, in SQLite itself.
func TestSchemaClosedVocabularies(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueue(t, s, "d1", envA, JobDeploy, 1)
	enqueue(t, s, "d2", envA, JobTeardown, 2)

	check := func(name, stmt string, values []string, outside string) {
		t.Helper()
		for _, v := range values {
			if _, err := s.db.ExecContext(ctx, stmt, v); err != nil {
				t.Errorf("%s %q refused: %v", name, v, err)
			}
		}
		if _, err := s.db.ExecContext(ctx, stmt, outside); err == nil {
			t.Errorf("%s %q accepted", name, outside)
		}
	}
	failures := []string{}
	for _, f := range []Failure{FailureNone, FailureFetch, FailurePreflight, FailureBuild, FailureStage, FailureStart,
		FailureRoute, FailureCommit, FailureUnauthorized, FailureDiskFloor, FailureInterrupted} {
		failures = append(failures, string(f))
	}
	check("failure", `UPDATE jobs SET status = 'FAILED', finished_at = 1, failure = ? WHERE seq = 1`, failures, "oom")
	check("deploy origin", `UPDATE jobs SET origin = ? WHERE seq = 1`,
		[]string{string(OriginWebhook), string(OriginApproval)}, string(OriginTTL))
	check("teardown origin", `UPDATE jobs SET origin = ? WHERE seq = 2`,
		[]string{string(OriginWebhook), string(OriginRevocation), string(OriginRevalidation), string(OriginTTL)}, string(OriginApproval))
	check("deploy trust", `UPDATE jobs SET status = 'QUEUED', finished_at = 0, failure = '', trust = ? WHERE seq = 1`,
		[]string{string(TrustTrusted), string(TrustUntrusted), string(TrustUnclassified)}, "approved")
	check("teardown trust", `UPDATE jobs SET trust = ? WHERE seq = 2`, []string{string(TrustUnclassified)}, string(TrustTrusted))
	check("status", `UPDATE jobs SET status = ? WHERE seq = 1`,
		[]string{string(StatusQueued), string(StatusPendingApproval), string(StatusInProgress)}, "PARKED")

	reasons := []string{}
	for _, r := range []RevocationReason{RevokedDismissed, RevokedChangesRequested, RevokedUnlabeled, RevokedNewHead,
		RevokedApproverRemoved, RevokedPermissionLost, RevokedRevalidationUnavailable, RevokedPRClosed} {
		if !r.valid() {
			t.Errorf("reason %q not valid in Go", r)
		}
		reasons = append(reasons, string(r))
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO revocations (preview_id, commit_sha, revoked_seq, revoked_at, reason) VALUES (?, ?, 1, 1, 'dismissed')`,
		envA, testSource.CommitSHA); err != nil {
		t.Fatal(err)
	}
	check("revocation reason", `UPDATE revocations SET reason = ?`, reasons, "closed")

	n := int64(0)
	insertAudit := `INSERT INTO audit_events (id, at, kind, preview_id, repo, pr_number, commit_sha, actor_login, actor_id, detail, prev_hash, hash)
		VALUES (?, 1, ?, 'pr-1-0a0a0a0a0a', 'acme/app', 1, '', '', 0, ?, ?, ?)`
	auditRowOK := func(kind, detail string) error {
		n++
		h := fmt.Sprintf("%064x", n)
		_, err := s.db.ExecContext(ctx, insertAudit, n, kind, detail, zeroHash, h)
		return err
	}
	for _, kind := range []AuditKind{AuditTrustedDeploy, AuditUntrustedDeploy, AuditApprovalGranted, AuditApprovalRevoked,
		AuditDeployRefused, AuditTeardown, AuditTTLExpired, AuditFullSecretsOptIn} {
		details, ok := auditDetails(kind)
		if !ok || len(details) == 0 {
			t.Fatalf("kind %s has no detail vocabulary", kind)
		}
		for _, d := range details {
			if err := auditRowOK(string(kind), d); err != nil {
				t.Errorf("audit %s/%s refused: %v", kind, d, err)
			}
		}
	}
	if err := auditRowOK("deploy", "review"); err == nil {
		t.Error("audit kind outside the vocabulary accepted")
	}
	if err := auditRowOK(string(AuditTeardown), "because"); err == nil {
		t.Error("audit detail outside the vocabulary accepted")
	}
}

// B2: a database without incremental auto_vacuum (every file before schema
// 3) is converted at start; a fresh one too.
func TestNewStoreConvertsAutoVacuum(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	var mode int
	if err := db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil || mode != 0 {
		t.Fatalf("precondition: auto_vacuum = %d (%v), want 0", mode, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, path)
	if err := s.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil || mode != autoVacuumIncremental {
		t.Fatalf("auto_vacuum = %d (%v), want incremental", mode, err)
	}
}
