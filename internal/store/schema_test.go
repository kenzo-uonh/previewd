package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"regexp"
	"testing"
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
	if err := initializeSchema(context.Background(), db); err != nil {
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
		"secret text column":         `ALTER TABLE environments ADD COLUMN token TEXT`,
		"innocent text column":       `ALTER TABLE environments ADD COLUMN note TEXT`,
		"blob column":                `ALTER TABLE environments ADD COLUMN payload BLOB`,
		"untyped column":             `ALTER TABLE environments ADD COLUMN extra`,
		"varchar column":             `ALTER TABLE environments ADD COLUMN env VARCHAR(255)`,
		"new table":                  `CREATE TABLE jobs (id INTEGER PRIMARY KEY)`,
		"new table with blob":        `CREATE TABLE cache (k INTEGER, v BLOB)`,
		"allowlisted column retyped": `ALTER TABLE environments RENAME COLUMN status TO status_old; ALTER TABLE environments ADD COLUMN status BLOB`,
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
	if err := initializeSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `ALTER TABLE environments ADD COLUMN token TEXT`); err != nil {
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
