package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// liveStoreWithAudit is a store held open, as the running daemon holds it,
// with n audit rows still in the WAL (no checkpoint).
func liveStoreWithAudit(t *testing.T, n int) (*Store, string) {
	t.Helper()
	s, path := sweptStore(t)
	for i := range n {
		e := testAuditEvent(AuditApprovalGranted, "review")
		e.ActorLogin, e.ActorID = "lead-dev", 7
		if err := s.AppendAudit(context.Background(), e, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return s, path
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func mustHead(t *testing.T, path string) AuditHead {
	t.Helper()
	head, err := openReader(t, path).Verify(context.Background())
	if err != nil {
		t.Fatalf("verify %s: %v", path, err)
	}
	return head
}

// The backup of a database the daemon still holds open contains every
// committed row, WAL frames included, and is one self-contained file.
func TestBackupSnapshotsALiveDatabase(t *testing.T) {
	_, src := liveStoreWithAudit(t, 6)
	if fi, err := os.Stat(src + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("precondition: the rows must be in the WAL, not the file (stat %v, %v)", fi, err)
	}
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "previewd.backup")

	head, err := Backup(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if head.Rows != 6 {
		t.Fatalf("head = %+v, want 6 rows", head)
	}
	if got := mustHead(t, dst); got != head {
		t.Fatalf("the backup's chain ends at %+v, Backup reported %+v", got, head)
	}
	if want := mustHead(t, src); want != head {
		t.Fatalf("source head %+v, backup head %+v", want, head)
	}
	if names := dirNames(t, dstDir); len(names) != 1 || names[0] != "previewd.backup" {
		t.Fatalf("backup directory holds %v, want the backup alone (no WAL, no temporary file)", names)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v (%v), want 0600", fi.Mode(), err)
	}
}

// Backup takes no write lock: the daemon keeps committing while it runs and
// the snapshot is still a valid chain.
func TestBackupDoesNotBlockTheWriter(t *testing.T) {
	s, src := liveStoreWithAudit(t, 3)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var writes int
	var writeErr error
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			e := testAuditEvent(AuditTrustedDeploy, "write_access")
			if err := s.AppendAudit(context.Background(), e, t0.Add(time.Hour+time.Duration(i)*time.Second)); err != nil {
				writeErr = err
				return
			}
			writes++
		}
	})
	dst := filepath.Join(t.TempDir(), "previewd.backup")
	head, err := Backup(context.Background(), src, dst)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if writeErr != nil {
		t.Fatalf("the writer failed during the backup: %v", writeErr)
	}
	if writes == 0 {
		t.Fatal("the writer never committed")
	}
	if got := mustHead(t, dst); got != head || head.Rows < 3 {
		t.Fatalf("backup chain %+v, reported %+v", got, head)
	}
}

func TestBackupRefusesToOverwrite(t *testing.T) {
	_, src := liveStoreWithAudit(t, 2)
	dst := filepath.Join(t.TempDir(), "previewd.backup")
	if err := os.WriteFile(dst, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Backup(context.Background(), src, dst); !errors.Is(err, ErrBackup) {
		t.Fatalf("err = %v, want ErrBackup", err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "precious" {
		t.Fatalf("the existing file was touched: %q, %v", b, err)
	}
}

func TestBackupRefusesBadPaths(t *testing.T) {
	_, src := liveStoreWithAudit(t, 1)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.sqlite")
	for name, tc := range map[string]struct{ src, dst string }{
		"destination is the source":   {src, src},
		"destination dir is missing":  {src, filepath.Join(dir, "no", "such", "dir", "b")},
		"empty destination":           {src, ""},
		"destination with a query":    {src, filepath.Join(dir, "b?mode=rw")},
		"destination with a fragment": {src, filepath.Join(dir, "b#1")},
		"empty source":                {"", filepath.Join(dir, "b")},
		"source is missing":           {missing, filepath.Join(dir, "b")},
		"source with a query":         {src + "?mode=rw", filepath.Join(dir, "b")},
	} {
		if _, err := Backup(context.Background(), tc.src, tc.dst); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A refused backup creates nothing, the missing source in particular:
	// opening it read-only must not conjure an empty database.
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing source was created: %v", err)
	}
	if names := dirNames(t, dir); len(names) != 0 {
		t.Errorf("refused backups left %v", names)
	}
}

// A broken audit chain is not backed up as if it were sound: the backup
// fails, names the break, and leaves neither the file nor a temporary one.
func TestBackupRefusesABrokenChain(t *testing.T) {
	src := auditDB(t, 5)
	tamper(t, src, `UPDATE audit_events SET actor_login = 'mallory', actor_id = 666 WHERE id = 3`)
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "previewd.backup")

	_, err := Backup(context.Background(), src, dst)
	if !errors.Is(err, ErrAuditChain) || !strings.Contains(err.Error(), "row 3") {
		t.Fatalf("err = %v, want ErrAuditChain naming row 3", err)
	}
	if names := dirNames(t, dstDir); len(names) != 0 {
		t.Fatalf("a failed backup left %v", names)
	}
}

func TestBackupHonoursCancellation(t *testing.T) {
	_, src := liveStoreWithAudit(t, 1)
	dstDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Backup(ctx, src, filepath.Join(dstDir, "b")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if names := dirNames(t, dstDir); len(names) != 0 {
		t.Fatalf("a cancelled backup left %v", names)
	}
}

// The backup is a database the daemon can open and append to, and its
// journal mode is not WAL (it is read in a directory the daemon may not own).
func TestBackupIsAnOpenableSelfContainedDatabase(t *testing.T) {
	src := auditDB(t, 4)
	dst := filepath.Join(t.TempDir(), "previewd.backup")
	if _, err := Backup(context.Background(), src, dst); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	db, err := sql.Open("sqlite", dst)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if mode != "delete" {
		t.Fatalf("journal_mode = %q, want delete", mode)
	}
	s, err := NewStore(context.Background(), dst)
	if err != nil {
		t.Fatalf("the daemon cannot open the backup: %v", err)
	}
	if err := s.AppendAudit(context.Background(), testAuditEvent(AuditTrustedDeploy, "write_access"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// backupOf backs up a database of n audit rows and returns the backup path.
func backupOf(t *testing.T, n int) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "previewd.backup")
	if _, err := Backup(context.Background(), auditDB(t, n), dst); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	return dst
}

func TestRestoreRoundTrip(t *testing.T) {
	backup := backupOf(t, 5)
	want := mustHead(t, backup)
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "previewd.sqlite")

	head, err := Restore(context.Background(), backup, dst, RestoreOptions{})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if head != want || head.Rows != 5 {
		t.Fatalf("restored head %+v, backup head %+v", head, want)
	}
	if got := mustHead(t, dst); got != want {
		t.Fatalf("the restored chain ends at %+v, want %+v", got, want)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("restored mode = %v (%v), want 0600", fi.Mode(), err)
	}
	if names := dirNames(t, dstDir); len(names) != 1 {
		t.Fatalf("restore directory holds %v, want the database alone", names)
	}
	// The daemon opens it and carries on the chain.
	s, err := NewStore(context.Background(), dst)
	if err != nil {
		t.Fatalf("the daemon cannot open the restored database: %v", err)
	}
	if err := s.AppendAudit(context.Background(), testAuditEvent(AuditTrustedDeploy, "write_access"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAudit(context.Background()); err != nil {
		t.Fatalf("chain after a new row: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// A backup is checked again at restore: a snapshot altered since (the
// triggers dropped, a row rewritten) is refused, and the target is untouched.
func TestRestoreRefusesATamperedBackup(t *testing.T) {
	backup := backupOf(t, 5)
	tamper(t, backup, `UPDATE audit_events SET actor_login = 'mallory', actor_id = 666 WHERE id = 4`)
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "previewd.sqlite")

	if _, err := Restore(context.Background(), backup, dst, RestoreOptions{}); !errors.Is(err, ErrAuditChain) {
		t.Fatalf("err = %v, want ErrAuditChain", err)
	}
	if names := dirNames(t, dstDir); len(names) != 0 {
		t.Fatalf("a refused restore left %v", names)
	}
}

func TestRestoreRefusesAMissingOrForeignBackup(t *testing.T) {
	dir := t.TempDir()
	notSQLite := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notSQLite, []byte("not a database, long enough to be mistaken for a header....."), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, backup := range map[string]string{
		"missing":        filepath.Join(dir, "missing.backup"),
		"not a database": notSQLite,
		"empty path":     "",
	} {
		dst := filepath.Join(t.TempDir(), "previewd.sqlite")
		if _, err := Restore(context.Background(), backup, dst, RestoreOptions{}); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a target was created: %v", name, err)
		}
	}
}

// The target's history is never destroyed by accident: an existing database
// is refused without Force, and with Force it is set aside, not deleted.
func TestRestoreNeverDestroysTheTarget(t *testing.T) {
	backup := backupOf(t, 3)
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "previewd.sqlite")
	if err := os.WriteFile(dst, []byte("the current database"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Restore(context.Background(), backup, dst, RestoreOptions{}); !errors.Is(err, ErrBackup) {
		t.Fatalf("without Force: err = %v, want ErrBackup", err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "the current database" {
		t.Fatalf("the target was touched: %q, %v", b, err)
	}

	if _, err := Restore(context.Background(), backup, dst, RestoreOptions{Force: true}); err != nil {
		t.Fatalf("with Force: %v", err)
	}
	if got := mustHead(t, dst); got.Rows != 3 {
		t.Fatalf("restored head %+v", got)
	}
	var aside []string
	for _, n := range dirNames(t, dstDir) {
		if strings.HasPrefix(n, "previewd.sqlite.replaced-") {
			aside = append(aside, n)
		}
	}
	if len(aside) != 1 {
		t.Fatalf("directory holds %v, want one set-aside copy", dirNames(t, dstDir))
	}
	if b, err := os.ReadFile(filepath.Join(dstDir, aside[0])); err != nil || string(b) != "the current database" {
		t.Fatalf("the replaced database is not kept intact: %q, %v", b, err)
	}
}

// -wal and -shm beside the target mean a daemon holds it or died holding it:
// replacing the file under it would corrupt both. Force does not override.
func TestRestoreRefusesALiveTarget(t *testing.T) {
	backup := backupOf(t, 2)
	for _, sidecar := range []string{"-wal", "-shm"} {
		dstDir := t.TempDir()
		dst := filepath.Join(dstDir, "previewd.sqlite")
		if err := os.WriteFile(dst, []byte("db"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst+sidecar, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Restore(context.Background(), backup, dst, RestoreOptions{Force: true}); !errors.Is(err, ErrBackup) {
			t.Errorf("%s: err = %v, want ErrBackup", sidecar, err)
		}
		if b, err := os.ReadFile(dst); err != nil || string(b) != "db" {
			t.Errorf("%s: the target was touched: %q, %v", sidecar, b, err)
		}
	}
}

// Adopt runs on the verified copy before it replaces anything; its failure
// aborts the restore and leaves no trace.
func TestRestoreAdoptHook(t *testing.T) {
	backup := backupOf(t, 2)
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "previewd.sqlite")

	var adopted string
	head, err := Restore(context.Background(), backup, dst, RestoreOptions{Adopt: func(path string) error {
		adopted = path
		if got := mustHead(t, path); got.Rows != 2 {
			t.Errorf("Adopt saw a copy with head %+v", got)
		}
		if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the target exists before Adopt ran: %v", err)
		}
		return nil
	}})
	if err != nil || head.Rows != 2 {
		t.Fatalf("Restore = %+v, %v", head, err)
	}
	if adopted == "" || adopted == dst || filepath.Dir(adopted) != dstDir {
		t.Fatalf("Adopt got %q, want a temporary file beside %s", adopted, dst)
	}

	failDir := t.TempDir()
	failDst := filepath.Join(failDir, "previewd.sqlite")
	boom := errors.New("chown refused")
	if _, err := Restore(context.Background(), backup, failDst, RestoreOptions{Adopt: func(string) error { return boom }}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the hook's error", err)
	}
	if names := dirNames(t, failDir); len(names) != 0 {
		t.Fatalf("an aborted restore left %v", names)
	}
}

// Publishing never replaces a file that appeared after the precheck: the
// destination is claimed atomically, or the backup is refused.
func TestPublishNewNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "staged")
	final := filepath.Join(dir, "previewd.backup")
	if err := os.WriteFile(tmp, []byte("the backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(final, []byte("created meanwhile"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishNew(tmp, final); !errors.Is(err, ErrBackup) {
		t.Fatalf("err = %v, want ErrBackup", err)
	}
	if b, err := os.ReadFile(final); err != nil || string(b) != "created meanwhile" {
		t.Fatalf("the file was overwritten: %q, %v", b, err)
	}

	// Free destination: the staged file takes the name and the temporary name goes.
	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	if err := publishNew(tmp, final); err != nil {
		t.Fatalf("publishNew: %v", err)
	}
	if b, err := os.ReadFile(final); err != nil || string(b) != "the backup" {
		t.Fatalf("published content %q, %v", b, err)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the staged name remains: %v", err)
	}
}
