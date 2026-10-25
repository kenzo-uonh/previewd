package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/envid"
)

var errNoJob = errors.New("the environment has no job")

// activityRecorder is the store: it counts the writes of each environment and the
// instants written.
type activityRecorder struct {
	mu      sync.Mutex
	writes  map[string][]time.Time
	unknown map[string]bool
	err     error
	block   chan struct{} // when set, a write waits on it
}

func newActivityRecorder() *activityRecorder {
	return &activityRecorder{writes: map[string][]time.Time{}, unknown: map[string]bool{}}
}

func (r *activityRecorder) UpdateLastActive(_ context.Context, envID string, at time.Time) error {
	if r.block != nil {
		<-r.block
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.unknown[envID]:
		return fmt.Errorf("record activity of %s: %w", envID, errNoJob)
	case r.err != nil:
		return r.err
	}
	r.writes[envID] = append(r.writes[envID], at)
	return nil
}

func (r *activityRecorder) count(envID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes[envID])
}

// clock is a settable time.
type clock struct{ ms atomic.Int64 }

func (c *clock) now() time.Time          { return time.UnixMilli(c.ms.Load()) }
func (c *clock) advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

func newTap(t *testing.T, rec *activityRecorder) (*ActivityTap, *clock) {
	t.Helper()
	tap, err := NewActivityTap(rec, func(err error) bool { return errors.Is(err, errNoJob) }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{}
	c.ms.Store(1_800_000_000_000)
	tap.now = c.now
	return tap, c
}

var (
	envOne   = envid.Generate("acme/app", "feature/a", 1)
	envTwo   = envid.Generate("acme/app", "feature/b", 2)
	envThree = envid.Generate("acme/other", "main", 3)
)

// Under heavy traffic the database sees at most one write per environment
// per minute, whatever the request rate, and the instant written is the
// latest request.
func TestActivityTapCoalescesHeavyTraffic(t *testing.T) {
	rec := newActivityRecorder()
	tap, c := newTap(t, rec)
	envs := []string{envOne, envTwo, envThree}

	stop := make(chan struct{})
	var observers sync.WaitGroup
	var observed atomic.Int64
	for g := range 32 {
		observers.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				tap.Observe(envs[(g+i)%len(envs)], c.now())
				observed.Add(1)
			}
		})
	}
	// Five minutes of traffic, flushed every second, with requests observed
	// within each second.
	for range 300 {
		for target := observed.Load() + 100; observed.Load() < target; {
			runtime.Gosched()
		}
		tap.Flush(context.Background())
		c.advance(time.Second)
	}
	close(stop)
	observers.Wait()
	c.advance(time.Minute)
	tap.Flush(context.Background())

	if observed.Load() < 10_000 {
		t.Fatalf("only %d requests observed: not heavy traffic", observed.Load())
	}
	for _, env := range envs {
		rec.mu.Lock()
		writes := rec.writes[env]
		rec.mu.Unlock()
		// 0 s, 60 s, ..., 240 s, then the final flush.
		if len(writes) < 5 || len(writes) > 6 {
			t.Errorf("%s: %d writes in 6 minutes of traffic, want one per minute", env, len(writes))
		}
		for i := 1; i < len(writes); i++ {
			if writes[i].Sub(writes[i-1]) < 0 {
				t.Errorf("%s: write %d moved back in time", env, i)
			}
		}
	}
}

// Observe never waits on the database: a write that hangs does not slow
// the requests observed meanwhile.
func TestActivityTapObserveNeverBlocks(t *testing.T) {
	rec := newActivityRecorder()
	rec.block = make(chan struct{})
	tap, c := newTap(t, rec)
	tap.Observe(envOne, c.now())

	flushed := make(chan struct{})
	go func() { tap.Flush(context.Background()); close(flushed) }()
	done := make(chan struct{})
	go func() {
		for range 100_000 {
			tap.Observe(envOne, c.now())
			tap.Observe(envTwo, c.now())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked behind a hung write")
	}
	close(rec.block)
	<-flushed
}

func TestActivityTapDropsWhatIsNotAnEnvironment(t *testing.T) {
	rec := newActivityRecorder()
	tap, c := newTap(t, rec)
	for _, bad := range []string{"", "api", "Pr-1-x", "pr-1-0a0a0a0a0a@file", strings.Repeat("a", 64), "../x"} {
		if tap.Observe(bad, c.now()) {
			t.Errorf("Observe(%q) tracked", bad)
		}
	}
	if tap.Observe(envOne, time.Time{}) || tap.Observe(envOne, time.Unix(0, 0)) {
		t.Error("an instant at or before the epoch was tracked")
	}
	tap.Flush(context.Background())
	if len(rec.writes) != 0 {
		t.Errorf("writes %v", rec.writes)
	}
}

// The tap's memory is bounded: past maxTrackedEnvironments, a new
// environment is dropped until one is forgotten.
func TestActivityTapBoundsWhatItTracks(t *testing.T) {
	tap, c := newTap(t, newActivityRecorder())
	for i := range maxTrackedEnvironments {
		if !tap.Observe(envid.Generate("acme/app", fmt.Sprint("b", i), uint64(i+1)), c.now()) {
			t.Fatalf("environment %d dropped below the bound", i)
		}
	}
	if tap.Observe(envid.Generate("acme/app", "one-too-many", 99999), c.now()) {
		t.Error("an environment beyond the bound was tracked")
	}
	if !tap.Observe(envid.Generate("acme/app", "b0", 1), c.now()) {
		t.Error("an environment already tracked was dropped")
	}
	tap.Flush(context.Background())
	c.advance(forgetAfter)
	tap.Flush(context.Background())
	if n := tap.tracked.Load(); n != 0 {
		t.Errorf("%d environments still tracked after %s idle", n, forgetAfter)
	}
	if !tap.Observe(envid.Generate("acme/app", "one-too-many", 99999), c.now()) {
		t.Error("the bound was not freed by forgetting idle environments")
	}
}

func TestActivityTapRetriesAfterTheIntervalAndForgetsTheUnknown(t *testing.T) {
	rec := newActivityRecorder()
	tap, c := newTap(t, rec)
	rec.err = errors.New("database is locked")
	tap.Observe(envOne, c.now())
	tap.Flush(context.Background())
	rec.err = nil
	// Not sooner than the interval, even after a failure.
	c.advance(30 * time.Second)
	tap.Flush(context.Background())
	if n := rec.count(envOne); n != 0 {
		t.Fatalf("%d writes 30 s after a failed one", n)
	}
	c.advance(30 * time.Second)
	tap.Flush(context.Background())
	if n := rec.count(envOne); n != 1 {
		t.Fatalf("%d writes a minute after a failed one, want the retry", n)
	}

	rec.unknown[envTwo] = true
	tap.Observe(envTwo, c.now())
	tap.Flush(context.Background())
	if _, ok := tap.envs.Load(envTwo); ok {
		t.Error("an environment the store does not know is still tracked")
	}
	// Nothing new: nothing written.
	c.advance(time.Hour)
	before := rec.count(envOne)
	tap.Flush(context.Background())
	if rec.count(envOne) != before {
		t.Error("an idle environment was written again")
	}
}

func TestNewActivityTapNeedsARecorder(t *testing.T) {
	if _, err := NewActivityTap(nil, func(error) bool { return false }, nil); err == nil {
		t.Error("a tap without a activityRecorder")
	}
	if _, err := NewActivityTap(newActivityRecorder(), nil, nil); err == nil {
		t.Error("a tap without the unknown predicate")
	}
}

const sampleMetrics = `# HELP traefik_router_requests_total How many HTTP requests are processed on a router, partitioned by service, status code, protocol, and method.
# TYPE traefik_router_requests_total counter
traefik_router_requests_total{code="200",method="GET",protocol="http",router="%[1]s@file",service="%[1]s@file"} %[3]d
traefik_router_requests_total{code="404",method="GET",protocol="http",router="%[1]s@file",service="%[1]s@file"} 2
traefik_router_requests_total{code="200",method="POST",protocol="http",router="%[2]s@file",service="%[2]s@file"} %[4]d
traefik_router_requests_total{code="200",method="GET",protocol="http",router="prometheus@internal",service="prometheus@internal"} 900
traefik_router_requests_total{code="200",method="GET",protocol="http",router="stray-name@file",service="x@file"} 5
traefik_router_request_duration_seconds_bucket{code="200",method="GET",protocol="http",router="%[1]s@file",service="%[1]s@file",le="0.1"} 7
traefik_open_connections{entrypoint="web",protocol="TCP"} 3
`

func TestParseRouterRequests(t *testing.T) {
	counts, err := parseRouterRequests(strings.NewReader(fmt.Sprintf(sampleMetrics, envOne, envTwo, 10, 3)))
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 2 || counts[envOne] != 12 || counts[envTwo] != 3 {
		t.Errorf("counts = %v; want %s 12 (summed over codes), %s 3, nothing else", counts, envOne, envTwo)
	}

	escaped := `traefik_router_requests_total{code="200",method="GET",note="a \"quoted\", \\ value\n",router="` + envOne + `@file"} 4 1700000000000`
	if counts, err := parseRouterRequests(strings.NewReader(escaped)); err != nil || counts[envOne] != 4 {
		t.Errorf("escaped labels and a timestamp: %v, %v", counts, err)
	}

	for name, line := range map[string]string{
		"no router":       `traefik_router_requests_total{code="200"} 1`,
		"unterminated":    `traefik_router_requests_total{router="` + envOne + `@file} 1`,
		"no value":        `traefik_router_requests_total{router="` + envOne + `@file"}`,
		"negative":        `traefik_router_requests_total{router="` + envOne + `@file"} -1`,
		"not a number":    `traefik_router_requests_total{router="` + envOne + `@file"} many`,
		"NaN":             `traefik_router_requests_total{router="` + envOne + `@file"} NaN`,
		"infinite":        `traefik_router_requests_total{router="` + envOne + `@file"} +Inf`,
		"bad escape":      `traefik_router_requests_total{router="a\qb"} 1`,
		"label twice":     `traefik_router_requests_total{router="` + envOne + `@file",router="` + envTwo + `@file"} 1`,
		"too many fields": `traefik_router_requests_total{router="` + envOne + `@file"} 1 2 3`,
	} {
		if _, err := parseRouterRequests(strings.NewReader(line)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := strings.Repeat("# padding padding padding padding\n", maxMetricsBytes/34+2)
	if _, err := parseRouterRequests(strings.NewReader(big)); err == nil {
		t.Error("a reply above the cap was read")
	}
}

// fakeTraefik serves the metrics endpoint with the counts the test sets.
type fakeTraefik struct {
	mu        sync.Mutex
	one, two  int
	status    int
	redirect  string
	requested atomic.Int64
}

func (f *fakeTraefik) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requested.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path != "/metrics":
		http.NotFound(w, r)
	case f.redirect != "":
		http.Redirect(w, r, f.redirect, http.StatusFound)
	case f.status != 0:
		w.WriteHeader(f.status)
	default:
		_, _ = fmt.Fprintf(w, sampleMetrics, envOne, envTwo, f.one, f.two)
	}
}

func (f *fakeTraefik) set(one, two int) {
	f.mu.Lock()
	f.one, f.two = one, two
	f.mu.Unlock()
}

func serveTraefik(t *testing.T, f *fakeTraefik) netip.AddrPort {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return netip.MustParseAddrPort(srv.Listener.Addr().String())
}

func TestTraefikMetricsReportsRoutersThatMoved(t *testing.T) {
	f := &fakeTraefik{one: 10, two: 3}
	rec := newActivityRecorder()
	tap, c := newTap(t, rec)
	m, err := NewTraefikMetrics(serveTraefik(t, f), tap, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	m.now = c.now
	read := func() {
		t.Helper()
		if err := m.Read(context.Background()); err != nil {
			t.Fatal(err)
		}
		tap.Flush(context.Background())
		c.advance(time.Minute)
	}

	// The first read is the baseline: the counters run from Traefik's
	// start, and a previewd restart is not traffic.
	read()
	if len(rec.writes) != 0 {
		t.Fatalf("the baseline was taken for activity: %v", rec.writes)
	}
	f.set(11, 3) // one request to envOne
	read()
	if rec.count(envOne) != 1 || rec.count(envTwo) != 0 {
		t.Fatalf("writes %v; want envOne only", rec.writes)
	}
	read() // nothing moved
	if rec.count(envOne) != 1 {
		t.Errorf("writes %v; an unchanged counter is no activity", rec.writes)
	}
	f.set(1, 3) // Traefik restarted, then served envOne
	read()
	if rec.count(envOne) != 2 {
		t.Errorf("writes %v; a counter that restarted above zero is activity", rec.writes)
	}
}

func TestTraefikMetricsFailsWithoutFollowingRedirects(t *testing.T) {
	other := &fakeTraefik{}
	otherAddr := serveTraefik(t, other)
	for name, f := range map[string]*fakeTraefik{
		"server error": {status: http.StatusInternalServerError},
		"redirect":     {redirect: "http://" + otherAddr.String() + "/metrics"},
	} {
		tap, _ := newTap(t, newActivityRecorder())
		m, err := NewTraefikMetrics(serveTraefik(t, f), tap, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Read(context.Background()); err == nil {
			t.Errorf("%s: read succeeded", name)
		}
	}
	if other.requested.Load() != 0 {
		t.Error("a redirect was followed")
	}

	tap, _ := newTap(t, newActivityRecorder())
	for _, bad := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:8082"), netip.MustParseAddrPort("172.30.255.2:0"),
		netip.MustParseAddrPort("[fe80::1%eth0]:8082")} {
		if _, err := NewTraefikMetrics(bad, tap, nil); err == nil {
			t.Errorf("address %s accepted", bad)
		}
	}
	if _, err := NewTraefikMetrics(netip.MustParseAddrPort("172.30.255.2:8082"), nil, nil); err == nil {
		t.Error("metrics without a tap")
	}
}

// Run logs a failing source once, not at every tick, and stops with ctx.
func TestTraefikMetricsRunLogsTransitions(t *testing.T) {
	f := &fakeTraefik{status: http.StatusServiceUnavailable}
	var logs strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), nil))
	tap, _ := newTap(t, newActivityRecorder())
	m, err := NewTraefikMetrics(serveTraefik(t, f), tap, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx, 5*time.Millisecond); close(done) }()
	for f.requested.Load() < 5 {
		time.Sleep(time.Millisecond)
	}
	f.mu.Lock()
	f.status = 0
	f.mu.Unlock()
	for f.requested.Load() < 10 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(logs.String(), "cannot be read"); n != 1 {
		t.Errorf("%d failure records, want one:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "recovered") {
		t.Errorf("no recovery record:\n%s", logs.String())
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

var _ io.Writer = writerFunc(nil)
