package main

// previewd list | status ENV (V1.2 spec 3.3): the environments the queue
// knows, what was last asked of each, and when each last served a request.
// Read-only beside a running daemon, or on a copy; neither needs the
// daemon's configuration or credentials.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/textutil"
)

// statusTimeout bounds one list or status.
const statusTimeout = time.Minute

// exitNotFound is status's exit code for an environment the queue does not
// know.
const exitNotFound = 1

const statusUsage = `usage:
  previewd list [-db PATH] [-json]
      List every environment the queue knows: its state, repository, pull
      request, commit, latest job and when it last served an HTTP request
      ("never" when no request was recorded since V1.2).
  previewd status [-db PATH] [-json] ENVIRONMENT_ID
      Show one environment. Exit 1 if the queue does not know it.

PATH defaults to PREVIEWD_DB_PATH, then previewd.sqlite. The database is
opened read-only and never migrated.
`

// envView is one environment as list and status print it.
type envView struct {
	Environment string     `json:"environment_id"`
	State       string     `json:"state"`
	Repository  string     `json:"repository"`
	PullRequest int64      `json:"pull_request"`
	Commit      string     `json:"commit_sha"`
	Job         int64      `json:"job_id"`
	JobType     string     `json:"job_type"`
	JobStatus   string     `json:"job_status"`
	Failure     string     `json:"failure,omitempty"`
	Updated     time.Time  `json:"updated_at"`
	LastActive  *time.Time `json:"last_active_at"`
}

func view(st store.EnvironmentStatus) envView {
	j := st.Latest
	updated := j.FinishedAt
	if updated == 0 {
		updated = j.CreatedAt
	}
	v := envView{
		Environment: j.EnvID, State: st.State(), Repository: printable(j.Source.Repo), PullRequest: j.Source.PRNumber,
		Commit: j.Source.CommitSHA, Job: j.ID, JobType: string(j.Type), JobStatus: string(j.Status), Failure: string(j.Failure),
		Updated: time.UnixMilli(updated).UTC(),
	}
	if !st.LastActive.IsZero() {
		at := st.LastActive
		v.LastActive = &at
	}
	return v
}

// printable replaces every rune a terminal could act on (controls, escape
// sequences, invalid UTF-8) with '?'. Every value printed was validated
// where it entered; this keeps a tampered database from writing to the
// operator's terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}

// ago renders the last activity relative to now.
func ago(at *time.Time, now time.Time) string {
	if at == nil {
		return "never"
	}
	d := now.Sub(*at).Truncate(time.Second)
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%s (%s ago)", at.Format("2006-01-02 15:04 UTC"), d)
}

// runStatus is `previewd list` (cmd "list") and `previewd status` (cmd
// "status").
func runStatus(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer, now func() time.Time) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := statusCommand(ctx, cmd, args, out, diag, now)
	if code == exitOK && out.err != nil {
		diag.printf("previewd %s: write the result: %v\n", cmd, out.err)
		return exitUsage
	}
	return code
}

func statusCommand(ctx context.Context, cmd string, args []string, out, diag *console, now func() time.Time) int {
	fs := flag.NewFlagSet("previewd "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dbPath := fs.String("db", config.DBPath(), "")
	asJSON := fs.Bool("json", false, "")
	wantArgs := map[string]int{"list": 0, "status": 1}[cmd]
	if err := fs.Parse(args); err != nil || fs.NArg() != wantArgs {
		diag.printf("previewd %s: invalid arguments\n%s", cmd, statusUsage)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	r, err := store.OpenStatusReader(ctx, *dbPath)
	if err != nil {
		diag.printf("previewd %s: %v\n", cmd, err)
		return exitUsage
	}
	defer func() {
		if err := r.Close(); err != nil {
			diag.printf("previewd %s: close: %v\n", cmd, err)
		}
	}()

	var views []envView
	if cmd == "status" {
		st, found, err := r.Environment(ctx, fs.Arg(0))
		switch {
		case err != nil:
			diag.printf("previewd status: %v\n", err)
			return exitUsage
		case !found:
			diag.printf("previewd status: no environment %s\n", textutil.Truncate(printable(fs.Arg(0)), 64))
			return exitNotFound
		}
		views = []envView{view(st)}
	} else {
		all, err := r.Environments(ctx)
		if err != nil {
			diag.printf("previewd list: %v\n", err)
			return exitUsage
		}
		for _, st := range all {
			views = append(views, view(st))
		}
	}

	if *asJSON {
		var doc any = views
		if cmd == "status" {
			doc = views[0]
		} else if views == nil {
			doc = []envView{}
		}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			diag.printf("previewd %s: encode: %v\n", cmd, err)
			return exitUsage
		}
		out.printf("%s\n", b)
		return exitOK
	}
	if cmd == "status" {
		v := views[0]
		out.printf("environment:  %s\nstate:        %s\nrepository:   %s\npull request: %d\ncommit:       %s\n",
			v.Environment, v.State, v.Repository, v.PullRequest, v.Commit)
		out.printf("latest job:   %d (%s %s", v.Job, v.JobType, v.JobStatus)
		if v.Failure != "" {
			out.printf(", failed at %s", v.Failure)
		}
		out.printf(") at %s\nlast active:  %s\n", v.Updated.Format("2006-01-02 15:04 UTC"), ago(v.LastActive, now()))
		return exitOK
	}
	tw := tabwriter.NewWriter(out.w, 0, 0, 2, ' ', 0)
	table := &console{w: tw}
	table.printf("ENVIRONMENT\tSTATE\tREPOSITORY\tPR\tCOMMIT\tJOB\tLAST ACTIVE\n")
	for _, v := range views {
		table.printf("%s\t%s\t%s\t%d\t%.12s\t%d %s %s\t%s\n", v.Environment, v.State, v.Repository, v.PullRequest,
			v.Commit, v.Job, v.JobType, v.JobStatus, ago(v.LastActive, now()))
	}
	if err := errors.Join(table.err, tw.Flush()); err != nil && out.err == nil {
		out.err = err
	}
	return exitOK
}
