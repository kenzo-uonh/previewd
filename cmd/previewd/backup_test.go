package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runBackupCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runBackup(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func runRestoreCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runRestore(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestBackupWritesAVerifiedSnapshot(t *testing.T) {
	db := trail(t)
	out := filepath.Join(t.TempDir(), "previewd.backup")

	code, stdout, stderr := runBackupCmd(t, "-db", db, "-out", out)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "5 audit rows") {
		t.Fatalf("backup = %d, %q, %q", code, stdout, stderr)
	}
	// The head it printed is the head of both the source and the backup.
	_, verified, _ := audit(t, "verify", "-db", out)
	_, source, _ := audit(t, "verify", "-db", db)
	head := headLine.FindStringSubmatch(verified)[1]
	if headLine.FindStringSubmatch(source)[1] != head || !strings.Contains(stdout, head) {
		t.Fatalf("heads differ: printed %q, backup %q, source %q", stdout, verified, source)
	}
}

func TestBackupReadsTheDatabasePathFromTheEnvironment(t *testing.T) {
	t.Setenv("PREVIEWD_DB_PATH", trail(t))
	out := filepath.Join(t.TempDir(), "previewd.backup")
	if code, stdout, stderr := runBackupCmd(t, "-out", out); code != exitOK {
		t.Fatalf("backup = %d, %q, %q", code, stdout, stderr)
	}
}

// A broken chain exits 1 like `audit verify`, and writes nothing.
func TestBackupOfABrokenChainExitsBroken(t *testing.T) {
	db := trail(t)
	rawSQL(t, db, `UPDATE audit_events SET actor_login = 'mallory', actor_id = 666 WHERE id = 3`)
	dir := t.TempDir()
	code, stdout, stderr := runBackupCmd(t, "-db", db, "-out", filepath.Join(dir, "b"))
	if code != exitBroken || stdout != "" || !strings.Contains(stderr, "BROKEN") {
		t.Fatalf("backup = %d, %q, %q", code, stdout, stderr)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("a refused backup left %v (%v)", entries, err)
	}
}

func TestBackupUsage(t *testing.T) {
	db := trail(t)
	existing := filepath.Join(t.TempDir(), "exists")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	for name, args := range map[string][]string{
		"no -out":            {"-db", db},
		"empty -out":         {"-db", db, "-out", ""},
		"extra argument":     {"-db", db, "-out", filepath.Join(outDir, "b"), "now"},
		"unknown flag":       {"-db", db, "-out", filepath.Join(outDir, "b"), "-wal"},
		"output exists":      {"-db", db, "-out", existing},
		"output into itself": {"-db", db, "-out", db},
		"missing database":   {"-db", filepath.Join(outDir, "absent.sqlite"), "-out", filepath.Join(outDir, "b")},
	} {
		if code, out, _ := runBackupCmd(t, args...); code != exitUsage || out != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d", name, code, out, exitUsage)
		}
	}
	if b, err := os.ReadFile(existing); err != nil || string(b) != "x" {
		t.Errorf("the existing output was touched: %q, %v", b, err)
	}
}

func TestBackupOutputFailureIsNotSuccess(t *testing.T) {
	var errOut bytes.Buffer
	out := filepath.Join(t.TempDir(), "b")
	if code := runBackup(context.Background(), []string{"-db", trail(t), "-out", out}, brokenPipe{}, &errOut); code != exitUsage {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	db := trail(t)
	backup := filepath.Join(t.TempDir(), "previewd.backup")
	if code, _, stderr := runBackupCmd(t, "-db", db, "-out", backup); code != exitOK {
		t.Fatalf("backup: %d %q", code, stderr)
	}
	target := filepath.Join(t.TempDir(), "previewd.sqlite")

	code, stdout, stderr := runRestoreCmd(t, "-in", backup, "-db", target)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, "5 audit rows") {
		t.Fatalf("restore = %d, %q, %q", code, stdout, stderr)
	}
	if code, out, _ := audit(t, "verify", "-db", target); code != exitOK || !strings.Contains(out, "5 rows") {
		t.Fatalf("restored trail: %d, %q", code, out)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("restored mode %v, %v; want 0600", fi.Mode(), err)
	}

	// The second restore needs -force, and sets the first aside.
	if code, _, _ := runRestoreCmd(t, "-in", backup, "-db", target); code != exitUsage {
		t.Fatalf("restore over a database without -force: exit %d, want %d", code, exitUsage)
	}
	if code, _, stderr := runRestoreCmd(t, "-in", backup, "-db", target, "-force"); code != exitOK {
		t.Fatalf("restore -force: %d, %q", code, stderr)
	}
	matches, err := filepath.Glob(target + ".replaced-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("set-aside copies: %v, %v", matches, err)
	}
}

func TestRestoreOfATamperedBackupExitsBroken(t *testing.T) {
	db := trail(t)
	backup := filepath.Join(t.TempDir(), "previewd.backup")
	if code, _, stderr := runBackupCmd(t, "-db", db, "-out", backup); code != exitOK {
		t.Fatalf("backup: %d %q", code, stderr)
	}
	rawSQL(t, backup, `DELETE FROM audit_events WHERE id = 2`)
	target := filepath.Join(t.TempDir(), "previewd.sqlite")
	code, _, stderr := runRestoreCmd(t, "-in", backup, "-db", target)
	if code != exitBroken || !strings.Contains(stderr, "BROKEN") {
		t.Fatalf("restore = %d, %q", code, stderr)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused restore created the target: %v", err)
	}
}

func TestRestoreUsage(t *testing.T) {
	target := filepath.Join(t.TempDir(), "previewd.sqlite")
	for name, args := range map[string][]string{
		"no -in":         {"-db", target},
		"missing backup": {"-in", filepath.Join(t.TempDir(), "absent"), "-db", target},
		"extra argument": {"-in", "x", "-db", target, "now"},
		"unknown flag":   {"-in", "x", "-db", target, "-yes"},
	} {
		if code, out, _ := runRestoreCmd(t, args...); code != exitUsage || out != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d", name, code, out, exitUsage)
		}
	}
}

// Run as root, restore must hand the database to the daemon's user: a
// root-owned 0600 file would keep the daemon out. The owner is the current
// database's, else the directory's; a non-root caller changes nothing.
func TestAdoptOwner(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "previewd.sqlite")
	staged := filepath.Join(dir, "previewd.sqlite.tmp-1")
	for _, p := range []string{db, staged} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type call struct {
		path     string
		uid, gid int
	}
	var calls []call
	chown := func(path string, uid, gid int) error { calls = append(calls, call{path, uid, gid}); return nil }

	if err := adoptOwner(staged, db, 1000, chown); err != nil || len(calls) != 0 {
		t.Fatalf("non-root: err %v, calls %v; want none", err, calls)
	}
	if err := adoptOwner(staged, db, 0, chown); err != nil || len(calls) != 1 || calls[0].path != staged || calls[0].uid != os.Getuid() || calls[0].gid != os.Getgid() {
		t.Fatalf("root, database present: err %v, calls %+v; want the owner of %s", err, calls, db)
	}
	// No database yet: the directory's owner.
	calls = nil
	if err := adoptOwner(staged, filepath.Join(dir, "absent.sqlite"), 0, chown); err != nil || len(calls) != 1 || calls[0].uid != os.Getuid() {
		t.Fatalf("root, no database: err %v, calls %+v", err, calls)
	}
	// A failing chown fails the adoption, and a missing directory too.
	boom := errors.New("operation not permitted")
	if err := adoptOwner(staged, db, 0, func(string, int, int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the chown error", err)
	}
	if err := adoptOwner(staged, filepath.Join(dir, "no", "such", "x"), 0, chown); err == nil {
		t.Fatal("a missing reference was accepted")
	}
}
