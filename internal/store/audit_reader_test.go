package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// auditDB writes n audit rows through the store, closes it (checkpointing
// the WAL into the file) and returns the file's path.
func auditDB(t *testing.T, n int) string {
	t.Helper()
	s, path := sweptStore(t)
	ctx := context.Background()
	kinds := []AuditEvent{
		testAuditEvent(AuditApprovalGranted, "review"),
		testAuditEvent(AuditTrustedDeploy, "write_access"),
		testAuditEvent(AuditApprovalRevoked, "dismissed"),
		testAuditEvent(AuditTeardown, "revalidation"),
		testAuditEvent(AuditFullSecretsOptIn, "opt_in"),
	}
	for i := range n {
		e := kinds[i%len(kinds)]
		e.ActorLogin, e.ActorID = "lead-dev", 7
		if err := s.AppendAudit(ctx, e, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// tamper runs stmts on the file with the append-only triggers dropped, as
// an attacker with write access to the file would.
func tamper(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	stmts = append([]string{`DROP TRIGGER audit_events_no_update`, `DROP TRIGGER audit_events_no_delete`}, stmts...)
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func openReader(t *testing.T, path string) *AuditReader {
	t.Helper()
	r, err := OpenAuditReader(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

// recompute is an independent implementation of the documented formula: an
// auditor's tool needs nothing but the export.
func recompute(rec AuditRecord) string {
	fields := []string{strconv.FormatInt(rec.ID, 10), strconv.FormatInt(rec.AtMillis, 10), rec.Kind, rec.EnvID, rec.Repo,
		strconv.FormatInt(rec.PRNumber, 10), rec.CommitSHA, rec.ActorLogin, strconv.FormatInt(rec.ActorID, 10), rec.Detail}
	var b strings.Builder
	b.WriteString(rec.PrevHash)
	b.WriteString("previewd-audit-v1\n")
	for _, f := range fields {
		b.WriteString(strconv.Itoa(len(f)) + ":" + f + ",")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func TestAuditReaderVerifiesAndExportsAnIntactChain(t *testing.T) {
	path := auditDB(t, 5)
	r := openReader(t, path)
	head, err := r.Verify(context.Background())
	if err != nil || head.Rows != 5 || len(head.Hash) != 64 {
		t.Fatalf("Verify = %+v, %v", head, err)
	}
	var out bytes.Buffer
	exported, err := r.Export(context.Background(), &out)
	if err != nil || exported != head {
		t.Fatalf("Export = %+v, %v; want %+v", exported, err, head)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("%d lines, want 5:\n%s", len(lines), out.String())
	}
	prev := zeroHash
	for i, line := range lines {
		var rec AuditRecord
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if rec.ID != int64(i+1) || rec.PrevHash != prev || recompute(rec) != rec.Hash || rec.ActorLogin != "lead-dev" ||
			rec.At != time.UnixMilli(rec.AtMillis).UTC().Format("2006-01-02T15:04:05.000Z07:00") {
			t.Fatalf("line %d does not verify independently: %s", i+1, line)
		}
		prev = rec.Hash
	}
	if prev != head.Hash {
		t.Fatalf("export ends at %s, head %s", prev, head.Hash)
	}
}

// D7: a row changed in the middle of a valid chain, with the triggers
// dropped, is a break; verify fails, and export stops after the last row
// that verifies.
func TestAuditReaderDetectsTampering(t *testing.T) {
	for name, tc := range map[string]struct {
		stmts []string
		want  string
	}{
		"actor rewritten":   {[]string{`UPDATE audit_events SET actor_login = 'mallory', actor_id = 666 WHERE id = 3`}, "row 3 does not match its hash"},
		"detail rewritten":  {[]string{`UPDATE audit_events SET detail = 'webhook' WHERE id = 3`}, "row 3 does not match its hash"},
		"time moved":        {[]string{`UPDATE audit_events SET at = at + 1 WHERE id = 3`}, "row 3 does not match its hash"},
		"row deleted":       {[]string{`DELETE FROM audit_events WHERE id = 3`}, "row 4 where 3 was expected"},
		"rows swapped":      {[]string{`UPDATE audit_events SET id = 1000 WHERE id = 3`, `UPDATE audit_events SET id = 3 WHERE id = 4`, `UPDATE audit_events SET id = 4 WHERE id = 1000`}, "row 3 does not follow row 2"},
		"one row re-hashed": {nil, "row 4 does not follow row 3"}, // filled below
		"row inserted": {[]string{`UPDATE audit_events SET id = id + 100 WHERE id >= 3`, `UPDATE audit_events SET id = id - 99 WHERE id >= 103`,
			`INSERT INTO audit_events SELECT 3, at, kind, preview_id, repo, pr_number, commit_sha, 'mallory', 666, detail, hash, '` + strings.Repeat("f", 64) + `' FROM audit_events WHERE id = 2`},
			"row 3 does not match its hash"},
		"first row's prev hash": {[]string{`UPDATE audit_events SET prev_hash = hash WHERE id = 1`}, "row 1 does not follow row 0"},
	} {
		t.Run(name, func(t *testing.T) {
			path := auditDB(t, 5)
			stmts := tc.stmts
			if stmts == nil {
				// The attacker recomputes the hash of the row they change; the
				// next row still names the old hash.
				r := openReader(t, path)
				var out bytes.Buffer
				if _, err := r.Export(context.Background(), &out); err != nil {
					t.Fatal(err)
				}
				var rec AuditRecord
				if err := json.Unmarshal([]byte(strings.Split(out.String(), "\n")[2]), &rec); err != nil {
					t.Fatal(err)
				}
				rec.ActorLogin = "mallory"
				stmts = []string{`UPDATE audit_events SET actor_login = 'mallory', hash = '` + recompute(rec) + `' WHERE id = 3`}
			}
			tamper(t, path, stmts...)
			r := openReader(t, path)
			if head, err := r.Verify(context.Background()); !errors.Is(err, ErrAuditChain) || !strings.Contains(err.Error(), tc.want) || head != (AuditHead{}) {
				t.Fatalf("Verify = %+v, %v; want ErrAuditChain %q", head, err, tc.want)
			}
			var out bytes.Buffer
			if _, err := r.Export(context.Background(), &out); !errors.Is(err, ErrAuditChain) {
				t.Fatalf("Export = %v, want ErrAuditChain", err)
			}
			if out.Len() != 0 {
				t.Fatalf("export of a broken chain wrote %d bytes:\n%s", out.Len(), out.String())
			}
		})
	}
}

// The reader never writes: the file is byte-identical after verify and
// export, and a write through it is refused.
func TestAuditReaderIsReadOnly(t *testing.T) {
	path := auditDB(t, 3)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := openReader(t, path)
	if _, err := r.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Export(context.Background(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.ExecContext(context.Background(), `CREATE TABLE intruder (x INTEGER)`); err == nil {
		t.Fatal("a write through the audit reader succeeded")
	}
	// Two controls: with query_only lifted on a connection, the file itself
	// is still opened read-only.
	conn, err := r.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `PRAGMA query_only = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `CREATE TABLE intruder (x INTEGER)`); err == nil {
		t.Fatal("the audit reader's file is writable once query_only is lifted")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the database file changed under the audit reader")
	}
}

// Fail closed: another schema version, a missing file or an odd path is
// refused before any row is read.
func TestOpenAuditReaderRefuses(t *testing.T) {
	path := auditDB(t, 1)
	tamper(t, path, `PRAGMA user_version = 2`)
	if r, err := OpenAuditReader(context.Background(), path); err == nil {
		_ = r.Close()
		t.Fatal("schema version 2 accepted")
	}
	for _, bad := range []string{"", t.TempDir() + "/absent.sqlite", "a?mode=rw", "a#b"} {
		if r, err := OpenAuditReader(context.Background(), bad); err == nil {
			_ = r.Close()
			t.Errorf("%q accepted", bad)
		}
	}
	empty := auditDB(t, 0)
	head, err := openReader(t, empty).Verify(context.Background())
	if err != nil || head != (AuditHead{Rows: 0, Hash: zeroHash}) {
		t.Fatalf("empty trail = %+v, %v", head, err)
	}
}
