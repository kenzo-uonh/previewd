package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
)

// trail writes five audit rows through the daemon's store and returns the
// database path.
func trail(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	ctx := context.Background()
	s, err := store.NewStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(1_800_000_000_000)
	for i, e := range []store.AuditEvent{
		{Kind: store.AuditApprovalGranted, Detail: "review", ActorLogin: "lead-dev", ActorID: 7},
		{Kind: store.AuditUntrustedDeploy, Detail: "review", ActorLogin: "lead-dev", ActorID: 7},
		{Kind: store.AuditApprovalRevoked, Detail: "dismissed", ActorLogin: "lead-dev", ActorID: 7},
		{Kind: store.AuditTeardown, Detail: "revocation"},
		{Kind: store.AuditTrustedDeploy, Detail: "write_access", ActorLogin: "opener", ActorID: 4242},
	} {
		e.EnvID, e.Repo, e.PRNumber, e.CommitSHA = "pr-7-0a0a0a0a0a", "acme/app", 7, strings.Repeat("a", 40)
		if err := s.AppendAudit(ctx, e, at.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// rawSQL edits the file as an attacker with write access would: the
// append-only triggers dropped first.
func rawSQL(t *testing.T, path string, stmts ...string) {
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
	for _, stmt := range append([]string{`DROP TRIGGER audit_events_no_update`, `DROP TRIGGER audit_events_no_delete`}, stmts...) {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func audit(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runAudit(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

var headLine = regexp.MustCompile(`head ([0-9a-f]{64})`)

func TestAuditVerifyAndExportAnIntactTrail(t *testing.T) {
	path := trail(t)
	code, out, errOut := audit(t, "verify", "-db", path)
	if code != exitOK || !strings.Contains(out, "audit chain intact: 5 rows") {
		t.Fatalf("verify = %d, %q, %q", code, out, errOut)
	}
	head := headLine.FindStringSubmatch(out)[1]
	if code, out, errOut := audit(t, "verify", "-db", path, "-head", head); code != exitOK {
		t.Fatalf("verify -head = %d, %q, %q", code, out, errOut)
	}
	code, out, errOut = audit(t, "export", "-db", path)
	if code != exitOK || !strings.Contains(errOut, "5 rows, head "+head) {
		t.Fatalf("export = %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("export wrote %d lines, want 5", len(lines))
	}
	for i, line := range lines {
		var rec store.AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.ID != int64(i+1) {
			t.Fatalf("line %d: %v: %s", i+1, err, line)
		}
	}
	var last store.AuditRecord
	if err := json.Unmarshal([]byte(lines[4]), &last); err != nil || last.Hash != head {
		t.Fatalf("last exported hash %s, head %s", last.Hash, head)
	}

	// PREVIEWD_DB_PATH is the default database.
	t.Setenv("PREVIEWD_DB_PATH", path)
	if code, out, _ := audit(t, "verify"); code != exitOK || !strings.Contains(out, head) {
		t.Fatalf("verify on PREVIEWD_DB_PATH = %d, %q", code, out)
	}
}

// D7: a row tampered with in the middle of a valid chain, through raw SQL
// with the triggers dropped, fails verify (exit 1, naming the row) and
// export (exit 1, nothing written).
func TestAuditVerifyDetectsATamperedRow(t *testing.T) {
	path := trail(t)
	rawSQL(t, path, `UPDATE audit_events SET actor_login = 'mallory', actor_id = 666 WHERE id = 3`)
	code, out, errOut := audit(t, "verify", "-db", path)
	if code != exitBroken || out != "" || !strings.Contains(errOut, "BROKEN") || !strings.Contains(errOut, "row 3 does not match its hash") {
		t.Fatalf("verify of a tampered trail = %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, out, errOut = audit(t, "export", "-db", path)
	if code != exitBroken || out != "" || !strings.Contains(errOut, "BROKEN") {
		t.Fatalf("export of a tampered trail = %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// Truncating the newest rows leaves a valid shorter chain; a head recorded
// earlier catches it.
func TestAuditVerifyAnchoredHeadCatchesTruncation(t *testing.T) {
	path := trail(t)
	_, out, _ := audit(t, "verify", "-db", path)
	head := headLine.FindStringSubmatch(out)[1]
	rawSQL(t, path, `DELETE FROM audit_events WHERE id >= 4`)
	if code, out, _ := audit(t, "verify", "-db", path); code != exitOK || !strings.Contains(out, "3 rows") {
		t.Fatalf("a truncated chain is still a chain: %d, %q", code, out)
	}
	code, _, errOut := audit(t, "verify", "-db", path, "-head", head)
	if code != exitBroken || !strings.Contains(errOut, "does not contain the anchored head") {
		t.Fatalf("verify -head after truncation = %d, %q", code, errOut)
	}
}

func TestAuditUsage(t *testing.T) {
	path := trail(t)
	for name, args := range map[string][]string{
		"no subcommand":     {},
		"unknown":           {"repair", "-db", path},
		"short head":        {"verify", "-db", path, "-head", "abc"},
		"uppercase head":    {"verify", "-db", path, "-head", strings.Repeat("A", 64)},
		"head on export":    {"export", "-db", path, "-head", strings.Repeat("a", 64)},
		"extra argument":    {"verify", "-db", path, "now"},
		"missing database":  {"verify", "-db", filepath.Join(t.TempDir(), "absent.sqlite")},
		"database in a URI": {"verify", "-db", path + "?mode=rw"},
	} {
		if code, out, _ := audit(t, args...); code != exitUsage || out != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d", name, code, out, exitUsage)
		}
	}
}

type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A result that cannot be written is not a success: an export into a
// closed pipe, or a verdict lost on stdout, exits 2.
func TestAuditOutputFailureIsNotSuccess(t *testing.T) {
	path := trail(t)
	for _, cmd := range []string{"verify", "export"} {
		var errOut bytes.Buffer
		if code := runAudit(context.Background(), []string{cmd, "-db", path}, brokenPipe{}, &errOut); code != exitUsage {
			t.Errorf("%s into a broken pipe: exit %d, stderr %q", cmd, code, errOut.String())
		}
	}
}
