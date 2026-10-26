package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func lastActive(t *testing.T, s *Store, env string) int64 {
	t.Helper()
	var ms int64
	if err := s.db.QueryRowContext(context.Background(), `SELECT last_active_at FROM activity WHERE preview_id = ?`, env).Scan(&ms); err != nil {
		t.Fatalf("activity of %s: %v", env, err)
	}
	return ms
}

func TestUpdateLastActiveKeepsTheLatestInstant(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	enqueue(t, s, "d1", envA, JobDeploy, 100)

	if err := s.UpdateLastActive(ctx, envA, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateLastActive(ctx, envA, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A late write of an older instant never moves it back.
	if err := s.UpdateLastActive(ctx, envA, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, want := lastActive(t, s, envA), t0.Add(time.Minute).UnixMilli(); got != want {
		t.Errorf("last_active_at = %d, want %d", got, want)
	}
}

// Fails closed: nothing is recorded for a name the queue never had, so a
// stream of invented names cannot grow the table.
func TestUpdateLastActiveRefusesWhatTheQueueDoesNotKnow(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	if err := s.UpdateLastActive(ctx, envB, t0); !errors.Is(err, ErrNoJob) {
		t.Errorf("unknown environment: %v, want ErrNoJob", err)
	}
	for name, tc := range map[string]struct {
		env string
		at  time.Time
	}{
		"empty id":  {"", t0},
		"long id":   {string(make([]byte, 64)), t0},
		"zero time": {envA, time.Time{}},
		"the epoch": {envA, time.Unix(0, 0)},
		"before it": {envA, time.Unix(-1, 0)},
	} {
		if err := s.UpdateLastActive(ctx, tc.env, tc.at); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM activity`).Scan(&n); err != nil || n != 0 {
		t.Errorf("activity rows %d, %v; want none", n, err)
	}
}

func TestStatusReaderListsTheLatestJobAndActivity(t *testing.T) {
	s, path := sweptStore(t)
	ctx := context.Background()
	enqueue(t, s, "d1", envA, JobDeploy, 100)
	finish(t, s, acquire(t, s), StatusSuccess)
	enqueue(t, s, "d2", envB, JobDeploy, 100)
	enqueue(t, s, "d3", envB, JobTeardown, 200)
	if err := s.UpdateLastActive(ctx, envA, t0.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}

	r, err := OpenStatusReader(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	all, err := r.Environments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Latest.EnvID != envA || all[1].Latest.EnvID != envB {
		t.Fatalf("environments = %+v", all)
	}
	if !all[0].Running() || !all[0].LastActive.Equal(t0.Add(90*time.Second)) || all[0].LastActive.Location() != time.UTC {
		t.Errorf("%s = %+v; want running, active at t0+90s", envA, all[0])
	}
	if all[1].Running() || all[1].Latest.Type != JobTeardown || !all[1].LastActive.IsZero() {
		t.Errorf("%s = %+v; want its teardown, never active", envB, all[1])
	}

	one, ok, err := r.Environment(ctx, envA)
	if err != nil || !ok || one != all[0] {
		t.Errorf("Environment(%s) = %+v, %v, %v", envA, one, ok, err)
	}
	if _, ok, err := r.Environment(ctx, "pr-3-0c0c0c0c0c"); ok || err != nil {
		t.Errorf("unknown environment: %v, %v", ok, err)
	}
	if _, _, err := r.Environment(ctx, ""); err == nil {
		t.Error("an empty ID was looked up")
	}

	// The reader never writes.
	if _, err := r.db.ExecContext(ctx, `INSERT INTO activity (preview_id, last_active_at) VALUES ('x', 1)`); err == nil {
		t.Error("the status reader wrote to the database")
	}
}

func TestOpenStatusReaderRefusesBadPaths(t *testing.T) {
	for _, p := range []string{"", "a?b", "a#b", t.TempDir() + "/absent.sqlite"} {
		if r, err := OpenStatusReader(context.Background(), p); err == nil {
			_ = r.Close()
			t.Errorf("OpenStatusReader(%q) accepted", p)
		}
	}
}

// The daemon reads an environment as the status reader does (the trigger
// API's status route).
func TestStoreEnvironmentAndItsState(t *testing.T) {
	s, _ := sweptStore(t)
	ctx := context.Background()
	if _, ok, err := s.Environment(ctx, envA); ok || err != nil {
		t.Fatalf("before any job: %v, %v", ok, err)
	}
	enqueue(t, s, "d1", envA, JobDeploy, 100)
	st, ok, err := s.Environment(ctx, envA)
	if err != nil || !ok || st.State() != "deploying" || st.Running() {
		t.Fatalf("queued: %+v, %v, %v", st, ok, err)
	}
	finish(t, s, acquire(t, s), StatusSuccess)
	if err := s.UpdateLastActive(ctx, envA, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if st, _, _ = s.Environment(ctx, envA); st.State() != "running" || !st.Running() || !st.LastActive.Equal(t0.Add(time.Minute)) {
		t.Errorf("running: %+v", st)
	}
	if _, _, err := s.Environment(ctx, ""); err == nil {
		t.Error("an empty ID was looked up")
	}

	for want, j := range map[string]Job{
		"removed":           {Type: JobTeardown, Status: StatusSuccess},
		"removing":          {Type: JobTeardown, Status: StatusQueued},
		"running":           {Type: JobDeploy, Status: StatusSuccess},
		"awaiting-approval": {Type: JobDeploy, Status: StatusPendingApproval},
		"failed":            {Type: JobDeploy, Status: StatusFailed},
		"superseded":        {Type: JobDeploy, Status: StatusSkipped},
		"deploying":         {Type: JobDeploy, Status: StatusInProgress},
	} {
		if got := (EnvironmentStatus{Latest: j}).State(); got != want {
			t.Errorf("%s %s: State() = %q, want %q", j.Type, j.Status, got, want)
		}
	}
}
