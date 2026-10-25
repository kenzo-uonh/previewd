package store

// Online backup (previewd backup): a consistent snapshot of the live
// database through SQLite's backup API, WAL frames and the hash-chained
// audit trail included, while the daemon keeps running. The source is opened
// read-only: in WAL mode a reader takes no write lock and never blocks the
// daemon's writer (the checkpoint cannot pass it, so the WAL grows for the
// length of the copy). The snapshot is staged beside its destination,
// converted to a single self-contained file, checked (integrity, schema,
// whole audit chain) and only then renamed into place: a backup that
// exists has been verified, and a failed one leaves nothing behind.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"modernc.org/sqlite"
)

// ErrBackup is a backup or restore refused before it wrote anything: a
// path that cannot be used, or a destination that already exists.
var ErrBackup = errors.New("backup refused")

// Backup writes a verified snapshot of the database at src to dst and
// returns the head of its audit chain. dst must not exist and its directory
// must; the file is created 0600. Backup refuses a snapshot whose chain is
// broken (ErrAuditChain) or whose schema is not this binary's.
func Backup(ctx context.Context, src, dst string) (AuditHead, error) {
	srcAbs, err := backupPath("source", src)
	if err != nil {
		return AuditHead{}, err
	}
	dstAbs, err := backupPath("destination", dst)
	if err != nil {
		return AuditHead{}, err
	}
	if _, err := os.Stat(srcAbs); err != nil {
		return AuditHead{}, fmt.Errorf("backup: source: %w", err)
	}
	if err := mustNotExist(dstAbs); err != nil {
		return AuditHead{}, err
	}
	tmp, head, err := stage(ctx, srcAbs, dstAbs)
	if err != nil {
		return AuditHead{}, fmt.Errorf("backup: %w", err)
	}
	if err := publishNew(tmp, dstAbs); err != nil {
		return AuditHead{}, errors.Join(fmt.Errorf("backup: %w", err), removeStaged(tmp))
	}
	return head, nil
}

// RestoreOptions tunes Restore.
type RestoreOptions struct {
	// Force replaces an existing database at the destination. The old file
	// is renamed "<dst>.replaced-<UTC time>", never deleted: the audit trail
	// is never pruned.
	Force bool
	// Adopt, when set, runs on the verified temporary copy before it takes
	// the destination's name (the CLI gives it the daemon's owner). An error
	// aborts the restore.
	Adopt func(path string) error
}

// Restore puts the backup at backup in place as the database at dst and
// returns the head of its audit chain. The backup is copied into a
// temporary file beside dst, verified again (integrity, schema, the whole
// chain) and renamed into place, mode 0600: dst is either the old database
// or the verified new one, never a partial copy. It refuses an existing dst
// without Force, and a dst with a -wal, -shm or -journal file beside it
// (a daemon holds the database, or died holding it) always.
func Restore(ctx context.Context, backup, dst string, opts RestoreOptions) (AuditHead, error) {
	backupAbs, err := backupPath("backup", backup)
	if err != nil {
		return AuditHead{}, err
	}
	dstAbs, err := backupPath("destination", dst)
	if err != nil {
		return AuditHead{}, err
	}
	if fi, err := os.Stat(backupAbs); err != nil {
		return AuditHead{}, fmt.Errorf("restore: backup: %w", err)
	} else if !fi.Mode().IsRegular() {
		return AuditHead{}, fmt.Errorf("%w: backup %s is not a regular file", ErrBackup, backupAbs)
	}
	for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(dstAbs + sidecar); err == nil {
			return AuditHead{}, fmt.Errorf("%w: %s exists: the database is in use or was not closed cleanly; stop the daemon, then start it once to checkpoint, before restoring", ErrBackup, dstAbs+sidecar)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return AuditHead{}, fmt.Errorf("restore: %w", err)
		}
	}
	replacing := false
	switch fi, err := os.Lstat(dstAbs); {
	case err == nil && !opts.Force:
		return AuditHead{}, fmt.Errorf("%w: %s exists: restoring replaces the database and its audit trail; pass -force to set it aside first", ErrBackup, dstAbs)
	case err == nil && !fi.Mode().IsRegular():
		return AuditHead{}, fmt.Errorf("%w: %s is not a regular file", ErrBackup, dstAbs)
	case err == nil:
		replacing = true
	case !errors.Is(err, fs.ErrNotExist):
		return AuditHead{}, fmt.Errorf("restore: %w", err)
	}

	tmp, head, err := stage(ctx, backupAbs, dstAbs)
	if err != nil {
		return AuditHead{}, fmt.Errorf("restore: %w", err)
	}
	if opts.Adopt != nil {
		if err := opts.Adopt(tmp); err != nil {
			return AuditHead{}, errors.Join(fmt.Errorf("restore: adopt copy: %w", err), removeStaged(tmp))
		}
	}
	aside := ""
	if replacing {
		aside = dstAbs + ".replaced-" + time.Now().UTC().Format("20060102T150405Z")
		if err := mustNotExist(aside); err != nil {
			return AuditHead{}, errors.Join(err, removeStaged(tmp))
		}
		if err := os.Rename(dstAbs, aside); err != nil {
			return AuditHead{}, errors.Join(fmt.Errorf("restore: set the old database aside: %w", err), removeStaged(tmp))
		}
	}
	if err := publishNew(tmp, dstAbs); err != nil {
		err = errors.Join(fmt.Errorf("restore: %w", err), removeStaged(tmp))
		if aside != "" {
			if mvErr := os.Rename(aside, dstAbs); mvErr != nil {
				err = errors.Join(err, fmt.Errorf("restore: put the old database back from %s: %w", aside, mvErr))
			}
		}
		return AuditHead{}, err
	}
	return head, nil
}

// backupPath makes p absolute. SQLite reads '?' and '#' of a name as URI
// syntax: they are refused rather than silently truncating the path.
func backupPath(what, p string) (string, error) {
	if p == "" || strings.ContainsAny(p, "?#") {
		return "", fmt.Errorf("%w: %s path %s is empty or contains '?' or '#'", ErrBackup, what, quoted(p))
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%w: %s path: %w", ErrBackup, what, err)
	}
	return abs, nil
}

// mustNotExist refuses a path that exists, a dangling symbolic link
// included.
func mustNotExist(path string) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("%w: %s exists: it is never overwritten", ErrBackup, path)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("backup: %w", err)
	}
	return nil
}

// stage copies the database at src into a new temporary file beside final,
// makes it a single file, and verifies it. On any failure nothing is left
// behind.
func stage(ctx context.Context, src, final string) (string, AuditHead, error) {
	if err := ctx.Err(); err != nil {
		return "", AuditHead{}, err
	}
	tmp, err := createStaged(final)
	if err != nil {
		return "", AuditHead{}, err
	}
	head, err := fillStaged(ctx, src, tmp)
	if err != nil {
		return "", AuditHead{}, errors.Join(err, removeStaged(tmp))
	}
	return tmp, head, nil
}

func fillStaged(ctx context.Context, src, tmp string) (AuditHead, error) {
	if err := copyDatabase(ctx, src, tmp); err != nil {
		return AuditHead{}, err
	}
	head, err := verifyStaged(ctx, tmp)
	if err != nil {
		return AuditHead{}, err
	}
	if err := syncFile(tmp); err != nil {
		return AuditHead{}, err
	}
	return head, nil
}

// createStaged creates the temporary file next to final, mode 0600 from
// the first byte: SQLite would create it with the process umask.
func createStaged(final string) (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("temporary name: %w", err)
	}
	tmp := final + ".tmp-" + hex.EncodeToString(suffix[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- beside the operator's destination
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", errors.Join(fmt.Errorf("create temporary file: %w", err), os.Remove(tmp))
	}
	return tmp, nil
}

// removeStaged removes the temporary file and the sidecars SQLite may have
// made for it.
func removeStaged(tmp string) error {
	var errs []error
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		if err := os.Remove(tmp + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", tmp+suffix, err))
		}
	}
	return errors.Join(errs...)
}

// copyDatabase runs SQLite's online backup of src into the empty file dst
// in one step: one read transaction, so the snapshot is consistent whatever
// the daemon commits meanwhile. The call cannot be interrupted; the copy is
// bounded by the size of the database.
func copyDatabase(ctx context.Context, src, dst string) (err error) {
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: src, RawQuery: q.Encode()}).String())
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close source: %w", closeErr))
		}
	}()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("release source: %w", closeErr))
		}
	}()
	return conn.Raw(func(driverConn any) error {
		b, ok := driverConn.(interface {
			NewBackup(dstURI string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("the SQLite driver does not expose the online backup API")
		}
		bck, err := b.NewBackup(dst)
		if err != nil {
			return fmt.Errorf("start backup: %w", err)
		}
		_, stepErr := bck.Step(-1)
		if finishErr := bck.Finish(); finishErr != nil || stepErr != nil {
			return errors.Join(wrapIf("copy pages: %w", stepErr), wrapIf("finish backup: %w", finishErr))
		}
		return nil
	})
}

func wrapIf(format string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(format, err)
}

// verifyStaged turns the copy into a single file (journal mode DELETE: a
// copy of a WAL database must not need -wal and -shm files beside it),
// checks its integrity, then its schema version and its whole audit chain.
func verifyStaged(ctx context.Context, path string) (head AuditHead, err error) {
	if err := normalize(ctx, path); err != nil {
		return AuditHead{}, err
	}
	r, err := OpenAuditReader(ctx, path)
	if err != nil {
		return AuditHead{}, err
	}
	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close copy: %w", closeErr))
		}
	}()
	if head, err = r.Verify(ctx); err != nil {
		return AuditHead{}, err
	}
	return head, nil
}

func normalize(ctx context.Context, path string) (err error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open copy: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close copy: %w", closeErr))
		}
	}()
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode = DELETE`).Scan(&mode); err != nil {
		return fmt.Errorf("copy: journal mode: %w", err)
	}
	if mode != "delete" {
		return fmt.Errorf("copy: journal mode is %q after setting delete", mode)
	}
	var verdict string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&verdict); err != nil {
		return fmt.Errorf("copy: integrity check: %w", err)
	}
	if verdict != "ok" {
		return fmt.Errorf("copy: integrity check: %s", quoted(verdict))
	}
	return nil
}

func syncFile(path string) (err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- the staged copy
	if err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("sync %s: %w", path, closeErr))
		}
	}()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	return nil
}

// publishNew gives the staged copy the name final, which must not exist, and
// syncs the directory so the name survives a crash. The name is claimed with
// a hard link, which fails if anything holds it by then: a file created
// between the precheck and here is never overwritten. A file system without
// hard links falls back to a rename, whose window is the precheck's.
func publishNew(tmp, final string) error {
	linkErr := os.Link(tmp, final)
	switch {
	case linkErr == nil:
		if err := os.Remove(tmp); err != nil {
			return fmt.Errorf("remove the temporary name: %w", err)
		}
	case errors.Is(linkErr, fs.ErrExist):
		return fmt.Errorf("%w: %s exists: it is never overwritten", ErrBackup, final)
	default:
		if err := os.Rename(tmp, final); err != nil {
			return fmt.Errorf("rename into place: %w", errors.Join(err, fmt.Errorf("after link: %w", linkErr)))
		}
	}
	return syncDir(filepath.Dir(final))
}

func syncDir(dir string) (err error) {
	d, err := os.Open(dir) // #nosec G304 -- the destination's directory
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("sync %s: %w", dir, closeErr))
		}
	}()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
