//go:build storefixture

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
)

// TestWriteSchemaV2Fixture writes testdata/schema-v2-modernc.sqlite: a
// database at schema version 2, created by migrations 1 and 2 through the
// shipped driver and the production DSN, with a row for every job state
// schema 2 could hold. Run by make store-fixture-v2:
//
//	CGO_ENABLED=0 PREVIEWD_WRITE_STORE_FIXTURE=1 go test -tags storefixture \
//	  -run '^TestWriteSchemaV2Fixture$' ./internal/store/
//
// It refuses another driver than modernc.org/sqlite (CGO disabled), and an
// existing fixture: the committed file is evidence, never rewritten.
func TestWriteSchemaV2Fixture(t *testing.T) {
	if os.Getenv("PREVIEWD_WRITE_STORE_FIXTURE") != "1" {
		t.Skip("PREVIEWD_WRITE_STORE_FIXTURE=1 writes the fixture (make store-fixture-v2)")
	}
	driverVersion := shippedDriverVersion(t)
	for _, p := range []string{v2FixtureDB, v2FixtureMeta} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s exists: the committed fixture is not rewritten", p)
		}
	}
	if err := os.MkdirAll("testdata", 0o750); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	name, err := dsn(v2FixtureDB)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", name)
	if err != nil {
		t.Fatal(err)
	}
	for v := range 2 {
		if err := applyMigration(ctx, db, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range v2FixtureRows {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	meta := map[string]any{
		"driver": "modernc.org/sqlite", "driver_version": driverVersion, "go_version": runtime.Version(),
		"schema_version": 2,
	}
	var sqliteVersion string
	if err := db.QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&sqliteVersion); err != nil {
		t.Fatal(err)
	}
	meta["sqlite_version"] = sqliteVersion
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v2FixtureMeta, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s and %s (modernc.org/sqlite %s, SQLite %s)", v2FixtureDB, v2FixtureMeta, driverVersion, sqliteVersion)
}

// v2FixtureMeta records how the fixture was written.
const v2FixtureMeta = "testdata/schema-v2-modernc.json"

// v2FixtureRows are the rows of the fixture; TestMigrateSchemaV2Fixture
// states what migration 3 makes of each.
var v2FixtureRows = []string{
	`INSERT INTO boots (epoch, started_at) VALUES (1, 1790000000000), (2, 1790000600000)`,
	`INSERT INTO jobs (id, preview_id, type, seq, status, attempts, not_before, lease_epoch, repo, pr_number, commit_sha, clone_url) VALUES
		(1, 'pr-1-0a0a0a0a0a', 'deploy', 100, 'SUCCESS', 0, 0, 1, 'acme/app', 1, '1111111111111111111111111111111111111111', 'https://git.example.internal/acme/app.git'),
		(2, 'pr-1-0a0a0a0a0a', 'teardown', 200, 'QUEUED', 2, 1790000700000, 2, 'acme/app', 1, '1111111111111111111111111111111111111111', 'https://git.example.internal/acme/app.git'),
		(3, 'pr-2-0b0b0b0b0b', 'deploy', 150, 'SKIPPED', 0, 0, 0, 'acme/app', 2, '2222222222222222222222222222222222222222', 'https://git.example.internal/acme/app.git'),
		(4, 'pr-2-0b0b0b0b0b', 'deploy', 160, 'FAILED', 0, 0, 1, 'acme/app', 2, '3333333333333333333333333333333333333333', 'https://git.example.internal/acme/app.git'),
		(5, 'pr-2-0b0b0b0b0b', 'deploy', 170, 'IN_PROGRESS', 0, 0, 2, 'acme/app', 2, '4444444444444444444444444444444444444444', 'https://git.example.internal/acme/app.git'),
		(6, 'pr-3-0c0c0c0c0c', 'deploy', 300, 'QUEUED', 0, 0, 0, 'acme/sha256', 3, '5555555555555555555555555555555555555555555555555555555555555555', 'https://git.example.internal/acme/sha256.git')`,
	`INSERT INTO deliveries (delivery_id, payload_sha256, preview_id, seq, verdict) VALUES
		('d-1', '0000000000000000000000000000000000000000000000000000000000000001', 'pr-1-0a0a0a0a0a', 100, 'accepted'),
		('d-2', '0000000000000000000000000000000000000000000000000000000000000002', 'pr-1-0a0a0a0a0a', 200, 'accepted'),
		('d-3', '0000000000000000000000000000000000000000000000000000000000000003', 'pr-1-0a0a0a0a0a', 90, 'stale'),
		('d-4', '0000000000000000000000000000000000000000000000000000000000000004', 'pr-2-0b0b0b0b0b', 150, 'accepted')`,
}

func shippedDriverVersion(t *testing.T) string {
	t.Helper()
	if os.Getenv("CGO_ENABLED") != "0" {
		t.Fatal("CGO_ENABLED=0 is required: the fixture is written by the shipped, CGO-free driver")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build information")
	}
	for _, m := range info.Deps {
		if m.Path == "modernc.org/sqlite" {
			if m.Replace != nil {
				t.Fatalf("modernc.org/sqlite is replaced by %s", m.Replace.Path)
			}
			return m.Version
		}
	}
	t.Fatal("modernc.org/sqlite is not linked")
	return ""
}
