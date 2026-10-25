package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
)

var statusNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

const (
	runningEnv = "pr-7-0a0a0a0a0a"
	pendingEnv = "pr-8-0b0b0b0b0b"
	statusSHA  = "0123456789abcdef0123456789abcdef01234567"
)

// environments writes a database holding a running environment, active 5
// minutes before statusNow, and one still deploying, never active.
func environments(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	s, err := store.NewStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.StartupSweep(ctx, statusNow.Add(-time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	for i, env := range []string{runningEnv, pendingEnv} {
		src := store.Source{Repo: "acme.corp/app", HeadRepo: "acme.corp/app", PRNumber: int64(7 + i), OpenerLogin: "opener", OpenerID: 42,
			CommitSHA: statusSHA, CloneURL: "https://forge.corp/acme.corp/app.git"}
		if _, _, err := s.Enqueue(ctx, store.Delivery{ID: "d" + env, PayloadSHA256: strings.Repeat(string(rune('a'+i)), 64), EnvID: env,
			Type: store.JobDeploy, Seq: 100, Source: src, ReceivedAt: statusNow.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	l, ok, err := s.Acquire(ctx, statusNow.Add(-time.Hour))
	if err != nil || !ok {
		t.Fatalf("acquire: %v, %v", ok, err)
	}
	if err := s.Finish(ctx, l, store.StatusSuccess, statusNow.Add(-50*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if l.EnvID != runningEnv {
		t.Fatalf("leased %s first", l.EnvID)
	}
	if err := s.UpdateLastActive(ctx, runningEnv, statusNow.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	return path
}

func statusCmd(t *testing.T, cmd string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runStatus(context.Background(), cmd, args, &out, &errOut, func() time.Time { return statusNow })
	return code, out.String(), errOut.String()
}

func TestListShowsStateAndLastActivity(t *testing.T) {
	db := environments(t)
	code, out, errOut := statusCmd(t, "list", "-db", db)
	if code != exitOK || errOut != "" {
		t.Fatalf("list = %d, %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "ENVIRONMENT") {
		t.Fatalf("list:\n%s", out)
	}
	for _, want := range []string{runningEnv, "running", "acme.corp/app", "0123456789ab", "deploy SUCCESS", "2026-10-25 11:55 UTC (5m0s ago)"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("running line lacks %q: %s", want, lines[1])
		}
	}
	for _, want := range []string{pendingEnv, "deploying", "QUEUED", "never"} {
		if !strings.Contains(lines[2], want) {
			t.Errorf("deploying line lacks %q: %s", want, lines[2])
		}
	}

	code, out, _ = statusCmd(t, "list", "-db", db, "-json")
	var views []envView
	if err := json.Unmarshal([]byte(out), &views); code != exitOK || err != nil || len(views) != 2 {
		t.Fatalf("list -json = %d, %v:\n%s", code, err, out)
	}
	if views[0].LastActive == nil || !views[0].LastActive.Equal(statusNow.Add(-5*time.Minute)) || views[1].LastActive != nil {
		t.Errorf("last activity in JSON: %+v", views)
	}
}

func TestStatusShowsOneEnvironment(t *testing.T) {
	db := environments(t)
	code, out, _ := statusCmd(t, "status", "-db", db, runningEnv)
	if code != exitOK || !strings.Contains(out, "state:        running") || !strings.Contains(out, "last active:  2026-10-25 11:55 UTC (5m0s ago)") {
		t.Fatalf("status = %d:\n%s", code, out)
	}
	code, out, _ = statusCmd(t, "status", "-db", db, "-json", pendingEnv)
	var v envView
	if err := json.Unmarshal([]byte(out), &v); code != exitOK || err != nil || v.State != "deploying" || v.LastActive != nil {
		t.Fatalf("status -json = %d, %v: %+v", code, err, v)
	}
	if code, _, errOut := statusCmd(t, "status", "-db", db, "pr-9-0c0c0c0c0c"); code != exitNotFound || !strings.Contains(errOut, "no environment") {
		t.Errorf("unknown environment: %d, %q", code, errOut)
	}
	// A hostile argument is never echoed raw to the terminal.
	if _, _, errOut := statusCmd(t, "status", "-db", db, "pr-1-\x1b[31m"); strings.Contains(errOut, "\x1b") {
		t.Errorf("escape sequence echoed: %q", errOut)
	}
}

func TestListAndStatusRefuseBadArguments(t *testing.T) {
	db := environments(t)
	for name, tc := range map[string]struct {
		cmd  string
		args []string
	}{
		"list with an argument": {"list", []string{"-db", db, "x"}},
		"status without one":    {"status", []string{"-db", db}},
		"status with two":       {"status", []string{"-db", db, "a", "b"}},
		"unknown flag":          {"list", []string{"-db", db, "-x"}},
		"missing database":      {"list", []string{"-db", filepath.Join(t.TempDir(), "absent.sqlite")}},
	} {
		if code, _, errOut := statusCmd(t, tc.cmd, tc.args...); code != exitUsage || errOut == "" {
			t.Errorf("%s: %d, %q", name, code, errOut)
		}
	}
}
