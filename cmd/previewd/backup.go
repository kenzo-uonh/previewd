package main

// previewd backup | restore: a consistent snapshot of the live database and
// the way back (V1.1 spec, Day-2). Neither needs the daemon's configuration
// or credentials; backup runs beside the running daemon, restore needs it
// stopped.

import (
	"context"
	"flag"
	"io"
	"os"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/store"
)

// backupTimeout bounds one backup or restore, the integrity check and the
// audit chain walk included.
const backupTimeout = 30 * time.Minute

const backupUsage = `usage:
  previewd backup [-db PATH] -out BACKUP_PATH
      Write a consistent snapshot of the live database to BACKUP_PATH (mode
      0600, one self-contained file) without stopping the daemon or taking a
      write lock. The snapshot is verified before the command exits 0: SQLite
      integrity, schema version and the whole audit hash chain. BACKUP_PATH
      must not exist. Exit 1 if the audit chain is broken, 2 on any other
      failure.
  previewd restore -in BACKUP_PATH [-db PATH] [-force]
      Verify BACKUP_PATH again and put it in place as the database, mode 0600
      (owned like the current database, or its directory, when run as root).
      Stop the daemon first: a database with -wal or -shm files beside it is
      refused. An existing database is refused unless -force, which renames it
      to PATH.replaced-<UTC time>; nothing is ever deleted.

PATH defaults to PREVIEWD_DB_PATH, then previewd.sqlite.
`

// runBackup is `previewd backup`.
func runBackup(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := backupCommand(ctx, args, out, diag)
	if code == exitOK && out.err != nil {
		diag.printf("previewd backup: write the result: %v\n", out.err)
		return exitUsage
	}
	return code
}

func backupCommand(ctx context.Context, args []string, out, diag *console) int {
	fs := flag.NewFlagSet("previewd backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dbPath := fs.String("db", config.DBPath(), "")
	dst := fs.String("out", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dst == "" {
		diag.printf("previewd backup: invalid arguments\n%s", backupUsage)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	head, err := store.Backup(ctx, *dbPath, *dst)
	if err != nil {
		return auditFailure(diag, "backup", err)
	}
	out.printf("backup written: %s, %d audit rows, head %s\n", *dst, head.Rows, head.Hash)
	return exitOK
}

// runRestore is `previewd restore`.
func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := restoreCommand(ctx, args, out, diag)
	if code == exitOK && out.err != nil {
		diag.printf("previewd restore: write the result: %v\n", out.err)
		return exitUsage
	}
	return code
}

func restoreCommand(ctx context.Context, args []string, out, diag *console) int {
	fs := flag.NewFlagSet("previewd restore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dbPath := fs.String("db", config.DBPath(), "")
	in := fs.String("in", "", "")
	force := fs.Bool("force", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *in == "" {
		diag.printf("previewd restore: invalid arguments\n%s", backupUsage)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	head, err := store.Restore(ctx, *in, *dbPath, store.RestoreOptions{
		Force: *force,
		Adopt: func(path string) error { return adoptOwner(path, *dbPath, os.Geteuid(), os.Chown) },
	})
	if err != nil {
		return auditFailure(diag, "restore", err)
	}
	out.printf("database restored: %s, %d audit rows, head %s\n", *dbPath, head.Rows, head.Hash)
	return exitOK
}
