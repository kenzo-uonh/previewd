package proxy

// HTTP ingress activity sensing (V1.2 spec 3.3): when each environment last
// served a request, recorded without ever slowing a request or saturating
// the database's write lock.
//
// previewd is not in the request path: Traefik routes a preview's traffic
// straight to its container. The requests are counted where they pass, in
// Traefik's own per-router counters (Prometheus metrics on a dedicated
// entry point, bound to the proxy's address on previewd-proxy only), and
// read by TraefikMetrics on a timer. A router is named after its
// environment (Route.Document), so a counter that moved is an environment
// that served a request since the last read. This keeps previewd out of the
// data path on purpose: a forward-auth hook in each route would put the
// daemon in front of every request, hand it every request's headers
// (cookies, authorization), and turn a daemon restart into an outage of
// every preview.
//
// ActivityTap is the coalescing tap between the source and the store.
// Observe is non-blocking (a sync.Map lookup and an atomic store, no
// allocation for an environment already tracked), and Flush writes each
// environment at most once per ActivityFlushInterval whatever the traffic:
// the database sees at most one write per environment per minute.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenzo-uonh/previewd/internal/envid"
)

const (
	// ActivityFlushInterval is the shortest time between two writes of one
	// environment's activity.
	ActivityFlushInterval = time.Minute
	// maxTrackedEnvironments bounds the tap's memory: an environment beyond
	// it is not tracked until another one is forgotten.
	maxTrackedEnvironments = 4096
	// forgetAfter is how long an environment that served nothing stays
	// tracked after its last write.
	forgetAfter = 10 * ActivityFlushInterval
	// activityWriteTimeout bounds one write.
	activityWriteTimeout = 5 * time.Second
)

// ActivityRecorder persists an environment's latest activity
// (store.Store.UpdateLastActive).
type ActivityRecorder interface {
	UpdateLastActive(ctx context.Context, envID string, lastActive time.Time) error
}

// activityEntry is one tracked environment. Times are Unix milliseconds.
type activityEntry struct {
	seen    atomic.Int64 // the latest request observed
	written atomic.Int64 // the latest instant written
	flushed atomic.Int64 // when it was last written, or last tried
}

// ActivityTap coalesces observed requests per environment and writes them
// through its recorder.
type ActivityTap struct {
	rec     ActivityRecorder
	unknown func(error) bool
	logger  *slog.Logger
	now     func() time.Time
	every   time.Duration
	envs    sync.Map // environment ID -> *activityEntry
	tracked atomic.Int64
}

// NewActivityTap returns a tap writing through rec. unknown reports whether
// an error of rec means the environment is not tracked (store.ErrNoJob); a
// nil logger is slog.Default.
func NewActivityTap(rec ActivityRecorder, unknown func(error) bool, logger *slog.Logger) (*ActivityTap, error) {
	if rec == nil || unknown == nil {
		return nil, errors.New("activity tap: no recorder")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ActivityTap{rec: rec, unknown: unknown, logger: logger, now: time.Now, every: ActivityFlushInterval}, nil
}

// Observe records that envID served a request at t. It never blocks and
// never writes: Flush does. An invalid environment ID, or a new one while
// maxTrackedEnvironments are tracked, is dropped (false).
func (a *ActivityTap) Observe(envID string, t time.Time) bool {
	ms := t.UnixMilli()
	if ms <= 0 {
		return false
	}
	v, ok := a.envs.Load(envID)
	if !ok {
		if !envid.Valid(envID) || a.tracked.Load() >= maxTrackedEnvironments {
			return false
		}
		var loaded bool
		if v, loaded = a.envs.LoadOrStore(envID, &activityEntry{}); !loaded {
			a.tracked.Add(1)
		}
	}
	e := v.(*activityEntry)
	for {
		prev := e.seen.Load()
		if ms <= prev || e.seen.CompareAndSwap(prev, ms) {
			return true
		}
	}
}

// Flush writes the activity of every environment that served a request since
// its last write and was last written at least ActivityFlushInterval ago. A
// failed write is retried after the interval, never sooner; an environment
// the recorder does not know, or idle for forgetAfter, is forgotten.
func (a *ActivityTap) Flush(ctx context.Context) {
	now := a.now().UnixMilli()
	a.envs.Range(func(k, v any) bool {
		envID, e := k.(string), v.(*activityEntry)
		seen, flushed := e.seen.Load(), e.flushed.Load()
		switch {
		case seen <= e.written.Load():
			if now-flushed >= forgetAfter.Milliseconds() {
				a.forget(envID)
			}
			return true
		case flushed > 0 && now-flushed < a.every.Milliseconds():
			return true // throttled: at most one write per interval
		}
		e.flushed.Store(now)
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), activityWriteTimeout)
		err := a.rec.UpdateLastActive(wctx, envID, time.UnixMilli(seen))
		cancel()
		switch {
		case err == nil:
			e.written.Store(seen)
		case a.unknown(err):
			a.logger.Debug("Activity of an environment the queue does not know: forgotten", "environment_id", envID)
			a.forget(envID)
		default:
			a.logger.Warn("Could not record the activity of an environment: retried in a minute", "environment_id", envID, "error", err)
		}
		return true
	})
}

func (a *ActivityTap) forget(envID string) {
	if _, ok := a.envs.LoadAndDelete(envID); ok {
		a.tracked.Add(-1)
	}
}

// Run flushes every tick until ctx is done, then once more.
func (a *ActivityTap) Run(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.Flush(ctx)
			return
		case <-t.C:
			a.Flush(ctx)
		}
	}
}

const (
	// routerRequestsMetric is Traefik's request counter per router (with
	// metrics.prometheus.addRoutersLabels).
	routerRequestsMetric = "traefik_router_requests_total"
	// fileProviderSuffix ends the name of every router of the file provider.
	fileProviderSuffix = "@file"
	// maxMetricsBytes bounds one metrics reply.
	maxMetricsBytes = 8 << 20
	// metricsTimeout bounds one read of the metrics.
	metricsTimeout = 10 * time.Second
)

// TraefikMetrics reads Traefik's per-router request counters and reports to
// its tap every environment whose counter moved since the previous read.
type TraefikMetrics struct {
	url    string
	http   *http.Client
	tap    *ActivityTap
	logger *slog.Logger
	now    func() time.Time

	// last is each router's count at the previous read; primed once a read
	// succeeded (the first read is the baseline: the counters run from
	// Traefik's start, not previewd's).
	last    map[string]float64
	primed  bool
	failing bool
}

// NewTraefikMetrics returns a reader of the metrics served at addr (the
// proxy's metrics entry point, deployments/traefik.yml): plain HTTP to an
// IP literal on the proxy network, never through a proxy from the
// environment, never following a redirect.
func NewTraefikMetrics(addr netip.AddrPort, tap *ActivityTap, logger *slog.Logger) (*TraefikMetrics, error) {
	if !addr.IsValid() || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().Zone() != "" {
		return nil, fmt.Errorf("traefik metrics: invalid address %s", addr)
	}
	if tap == nil {
		return nil, errors.New("traefik metrics: no activity tap")
	}
	if logger == nil {
		logger = slog.Default()
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: metricsTimeout}).DialContext,
		ResponseHeaderTimeout: metricsTimeout,
		MaxIdleConns:          1,
		IdleConnTimeout:       time.Minute,
	}
	return &TraefikMetrics{
		url: "http://" + addr.String() + "/metrics",
		http: &http.Client{Timeout: metricsTimeout, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		tap: tap, logger: logger, now: time.Now, last: map[string]float64{},
	}, nil
}

// Read reads the counters once and observes, at the time of the read, every
// environment whose counter rose (or, Traefik having restarted since, fell
// to a count above zero).
func (m *TraefikMetrics) Read(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, metricsTimeout)
	defer cancel()
	counts, err := m.fetch(ctx)
	if err != nil {
		return err
	}
	at := m.now()
	for router, n := range counts {
		prev, known := m.last[router]
		moved := (known && n != prev && n > 0) || (!known && m.primed && n > 0)
		if moved {
			m.tap.Observe(router, at)
		}
	}
	m.last, m.primed = counts, true
	return nil
}

func (m *TraefikMetrics) fetch(ctx context.Context) (map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return nil, fmt.Errorf("traefik metrics: build request: %w", err)
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("traefik metrics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("traefik metrics: HTTP %d", resp.StatusCode)
	}
	counts, err := parseRouterRequests(io.LimitReader(resp.Body, maxMetricsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("traefik metrics: %w", err)
	}
	return counts, nil
}

// Run reads the counters every interval until ctx is done. A failed read is
// logged when the source starts failing and when it recovers, not at every
// tick: activity is information for operators, not a control.
func (m *TraefikMetrics) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		err := m.Read(ctx)
		switch {
		case err != nil && ctx.Err() == nil && !m.failing:
			m.failing = true
			m.logger.Warn("Ingress activity unknown: the Traefik metrics cannot be read", "url", m.url, "error", err)
		case err == nil && m.failing:
			m.failing = false
			m.logger.Info("Ingress activity sensing recovered", "url", m.url)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// parseRouterRequests sums, per environment, the routerRequestsMetric
// samples of a Prometheus text exposition read from r, which must hold at
// most maxMetricsBytes. Routers of other providers, and file routers whose
// name is not an environment ID, are left out. A malformed sample of that
// metric is an error, never skipped; other metrics are not parsed.
func parseRouterRequests(r io.Reader) (map[string]float64, error) {
	counts := map[string]float64{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	total := 0
	for sc.Scan() {
		line := sc.Text()
		if total += len(line) + 1; total > maxMetricsBytes {
			return nil, fmt.Errorf("reply exceeds %d bytes", maxMetricsBytes)
		}
		rest, ok := strings.CutPrefix(line, routerRequestsMetric+"{")
		if !ok {
			continue
		}
		labels, value, err := splitSample(rest)
		if err != nil {
			return nil, fmt.Errorf("%s sample: %w", routerRequestsMetric, err)
		}
		router, ok := labels["router"]
		if !ok {
			return nil, fmt.Errorf("%s sample without a router label", routerRequestsMetric)
		}
		env, ok := strings.CutSuffix(router, fileProviderSuffix)
		if !ok || !envid.Valid(env) {
			continue
		}
		counts[env] += value
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return counts, nil
}

// splitSample parses `k="v",...} value [timestamp]`, the rest of a sample
// line after its opening brace.
func splitSample(s string) (map[string]string, float64, error) {
	labels := map[string]string{}
	for {
		s = strings.TrimLeft(s, " ")
		if rest, ok := strings.CutPrefix(s, "}"); ok {
			s = rest
			break
		}
		name, rest, ok := strings.Cut(s, `="`)
		if !ok || name == "" || strings.ContainsAny(name, `{}",= `) {
			return nil, 0, errors.New("malformed label")
		}
		var b strings.Builder
		i := 0
		for ; i < len(rest) && rest[i] != '"'; i++ {
			if rest[i] == '\\' {
				if i++; i == len(rest) {
					break
				}
				switch rest[i] {
				case 'n':
					b.WriteByte('\n')
				case '\\', '"':
					b.WriteByte(rest[i])
				default:
					return nil, 0, errors.New("malformed escape in a label value")
				}
				continue
			}
			b.WriteByte(rest[i])
		}
		if i >= len(rest) {
			return nil, 0, errors.New("unterminated label value")
		}
		if _, dup := labels[name]; dup {
			return nil, 0, fmt.Errorf("label %q twice", name)
		}
		labels[name] = b.String()
		s = strings.TrimPrefix(rest[i+1:], ",")
	}
	fields := strings.Fields(s)
	if len(fields) == 0 || len(fields) > 2 {
		return nil, 0, errors.New("malformed value")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, 0, errors.New("the value is not a count")
	}
	return labels, v, nil
}
