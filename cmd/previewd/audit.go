package main

// previewd audit verify|export (V1 spec D7): read the hash-chained audit
// trail of the database without writing to it, beside a running daemon or
// on a copy. Neither needs the daemon's configuration or credentials.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/store"
)

// Exit codes of the audit subcommands.
const (
	exitOK     = 0
	exitBroken = 1 // the chain is broken, or the anchored head is missing
	exitUsage  = 2 // bad arguments, or the database cannot be read
)

// auditTimeout bounds one verify or export.
const auditTimeout = 10 * time.Minute

var headPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const auditUsage = `usage:
  previewd audit verify [-db PATH] [-head HASH]
      Recompute the hash chain from the first row. Exit 0 and print the row
      count and head hash when intact; exit 1 on any break. With -head, the
      chain must also contain HASH, a head recorded earlier (an export, a
      ticket): a chain truncated or rewritten since no longer holds it.
  previewd audit export [-db PATH]
      Verify the whole chain, then write it to standard output as JSON Lines,
      oldest first. A broken chain writes nothing and exits 1.

PATH defaults to PREVIEWD_DB_PATH, then previewd.sqlite. The database is
opened read-only and never migrated.
`

// console writes the CLI's output and keeps its first write error: a
// verdict that could not be written is not a verdict.
type console struct {
	w   io.Writer
	err error
}

func (c *console) printf(format string, args ...any) {
	if c.err == nil {
		_, c.err = fmt.Fprintf(c.w, format, args...)
	}
}

// runAudit runs "previewd audit ..." with args after "audit" and returns
// the exit code. A failed write to stdout turns a success into exitUsage.
func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := auditCommand(ctx, args, stdout, out, diag)
	if code == exitOK && out.err != nil {
		diag.printf("previewd audit: write the result: %v\n", out.err)
		return exitUsage
	}
	return code
}

func auditCommand(ctx context.Context, args []string, stdout io.Writer, out, diag *console) int {
	if len(args) == 0 {
		diag.printf("%s", auditUsage)
		return exitUsage
	}
	cmd := args[0]
	fs := flag.NewFlagSet("previewd audit "+cmd, flag.ContinueOnError)
	fs.SetOutput(diag.w)
	fs.Usage = func() { diag.printf("%s", auditUsage) }
	dbPath := fs.String("db", config.DBPath(), "database file")
	var head *string
	switch cmd {
	case "verify":
		head = fs.String("head", "", "a head hash the chain must contain")
	case "export":
	default:
		diag.printf("previewd audit: unknown subcommand %q\n%s", cmd, auditUsage)
		return exitUsage
	}
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		diag.printf("previewd audit %s: unexpected argument %q\n", cmd, fs.Arg(0))
		return exitUsage
	}
	if head != nil && *head != "" && !headPattern.MatchString(*head) {
		diag.printf("previewd audit verify: -head must be 64 lowercase hex characters\n")
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(ctx, auditTimeout)
	defer cancel()
	r, err := store.OpenAuditReader(ctx, *dbPath)
	if err != nil {
		diag.printf("previewd audit %s: %v\n", cmd, err)
		return exitUsage
	}
	defer func() {
		if err := r.Close(); err != nil {
			diag.printf("previewd audit %s: close: %v\n", cmd, err)
		}
	}()

	if cmd == "export" {
		h, err := r.Export(ctx, stdout)
		if err != nil {
			return auditFailure(diag, cmd, err)
		}
		diag.printf("audit trail exported: %d rows, head %s\n", h.Rows, h.Hash)
		return exitOK
	}
	h, err := r.Verify(ctx)
	if err != nil {
		return auditFailure(diag, cmd, err)
	}
	if *head != "" {
		found, err := r.Contains(ctx, *head)
		if err != nil {
			return auditFailure(diag, cmd, err)
		}
		if !found {
			diag.printf("previewd audit verify: BROKEN: the chain (%d rows, head %s) does not contain the anchored head %s: truncated or rewritten\n",
				h.Rows, h.Hash, *head)
			return exitBroken
		}
	}
	out.printf("audit chain intact: %d rows, head %s\n", h.Rows, h.Hash)
	return exitOK
}

// auditFailure reports err: a chain break exits 1, anything else 2.
func auditFailure(diag *console, cmd string, err error) int {
	if errors.Is(err, store.ErrAuditChain) {
		diag.printf("previewd audit %s: BROKEN: %v\n", cmd, err)
		return exitBroken
	}
	diag.printf("previewd audit %s: %v\n", cmd, err)
	return exitUsage
}

// subcommand runs a subcommand when os.Args names one, and reports whether
// it did; the daemon starts otherwise.
func subcommand() (code int, ran bool) {
	if len(os.Args) < 2 {
		return 0, false
	}
	switch os.Args[1] {
	case "audit":
		return runAudit(context.Background(), os.Args[2:], os.Stdout, os.Stderr), true
	default:
		diag := &console{w: os.Stderr}
		diag.printf("previewd: unknown command %q (run without arguments to start the daemon)\n%s", os.Args[1], auditUsage)
		return exitUsage, true
	}
}
