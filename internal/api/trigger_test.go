package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const triggerToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var triggerEnv = envid.Generate("acme/app", "feature/x", 7)

// fakeHeads is the forge a trigger reads.
type fakeHeads struct {
	head   vcs.Head
	err    error
	reads  int
	onRead func() // runs while the forge answers
}

func (f *fakeHeads) PullRequestHead(_ context.Context, project string, number uint32) (vcs.Head, error) {
	f.reads++
	if f.onRead != nil {
		f.onRead()
	}
	return f.head, f.err
}

// fakeEnvs is the store's view of the environments.
type fakeEnvs struct {
	envs map[string]store.EnvironmentStatus
	err  error
}

func (f *fakeEnvs) Environment(_ context.Context, envID string) (store.EnvironmentStatus, bool, error) {
	st, ok := f.envs[envID]
	return st, ok, f.err
}

type triggerHarness struct {
	*harness
	heads *fakeHeads
	envs  *fakeEnvs
}

func newTriggerHarness() *triggerHarness {
	h := newHarness()
	h.cfg.TriggerAPI = true
	h.cfg.PreviewScheme, h.cfg.TraefikDomain = "https", "preview.corp"
	return &triggerHarness{harness: h,
		heads: &fakeHeads{head: vcs.Head{Open: true, Ref: "feature/x", SHA: headSHA, HeadProject: "forker/app",
			CloneURL: "https://ghes.example/acme/app.git", Author: vcs.Account{Login: "forker", ID: 4242}}},
		envs: &fakeEnvs{envs: map[string]store.EnvironmentStatus{}},
	}
}

func (h *triggerHarness) server(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(slog.New(slog.DiscardHandler), h.cfg, []byte(testSecret), h.q, h.w, h.gh,
		WithTrigger([]byte(triggerToken), h.heads, h.envs))
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return h.now }
	return srv
}

func call(t *testing.T, srv *Server, method, path, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

const triggerBody = `{"repository":"acme/app","pull_request":7}`

func decodeReply(t *testing.T, rec *httptest.ResponseRecorder) triggerReply {
	t.Helper()
	var r triggerReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("reply %d %q: %v", rec.Code, rec.Body, err)
	}
	return r
}

// A trigger queues the head the forge reports, never one the caller names.
func TestTriggerQueuesTheForgesHead(t *testing.T) {
	h := newTriggerHarness()
	rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody)
	if rec.Code != http.StatusAccepted || h.w.n != 1 {
		t.Fatalf("reply %d %s, notified %d", rec.Code, rec.Body, h.w.n)
	}
	r := decodeReply(t, rec)
	if r.Status != "queued" || r.EnvironmentID != triggerEnv || r.JobID != 42 || r.PreviewURL != "https://"+triggerEnv+".preview.corp" {
		t.Errorf("reply = %+v", r)
	}
	if len(h.q.got) != 1 {
		t.Fatalf("deliveries %+v", h.q.got)
	}
	d := h.q.got[0]
	want := store.Source{Repo: "acme/app", HeadRepo: "forker/app", PRNumber: 7, OpenerLogin: "forker", OpenerID: 4242,
		CommitSHA: headSHA, CloneURL: "https://ghes.example/acme/app.git"}
	if d.Source != want || d.Type != store.JobDeploy || d.EnvID != triggerEnv || d.Seq != validate.SeqAt(v1Time) ||
		!strings.HasPrefix(d.ID, "trigger-") || len(d.ID) > 64 || len(d.PayloadSHA256) != 64 {
		t.Errorf("delivery = %+v", d)
	}
	// An untrusted head (a fork) is queued as any other deploy: the trigger
	// grants nothing, and the deploy gate decides from the forge.
	if len(h.q.grants) != 0 || len(h.q.revokes) != 0 {
		t.Errorf("a trigger recorded grants %+v or revocations %+v", h.q.grants, h.q.revokes)
	}

	// Two triggers are two intents, never replays of each other.
	call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody)
	if len(h.q.got) != 2 || h.q.got[0].ID == h.q.got[1].ID || h.q.got[0].PayloadSHA256 == h.q.got[1].PayloadSHA256 {
		t.Errorf("deliveries %+v", h.q.got)
	}
}

func TestTriggerNeverRebuildsTheHeadItIsAskedFor(t *testing.T) {
	for _, status := range []store.JobStatus{store.StatusQueued, store.StatusInProgress, store.StatusPendingApproval, store.StatusSuccess} {
		h := newTriggerHarness()
		h.envs.envs[triggerEnv] = store.EnvironmentStatus{Latest: store.Job{ID: 9, EnvID: triggerEnv, Type: store.JobDeploy, Status: status,
			Source: store.Source{CommitSHA: headSHA}}}
		rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody)
		if r := decodeReply(t, rec); rec.Code != http.StatusOK || r.Status != "current" || r.JobID != 9 || h.q.recorded() != 0 || h.w.n != 0 {
			t.Errorf("%s: reply %d %+v, recorded %d", status, rec.Code, r, h.q.recorded())
		}
	}
	// A failed deploy of that head, an older head or a teardown: queued.
	for name, latest := range map[string]store.Job{
		"failed":   {Type: store.JobDeploy, Status: store.StatusFailed, Source: store.Source{CommitSHA: headSHA}},
		"older":    {Type: store.JobDeploy, Status: store.StatusSuccess, Source: store.Source{CommitSHA: oldSHA}},
		"teardown": {Type: store.JobTeardown, Status: store.StatusSuccess, Source: store.Source{CommitSHA: headSHA}},
	} {
		h := newTriggerHarness()
		h.envs.envs[triggerEnv] = store.EnvironmentStatus{Latest: latest}
		if rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody); rec.Code != http.StatusAccepted || len(h.q.got) != 1 {
			t.Errorf("%s: reply %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestTriggerFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*triggerHarness)
		code int
	}{
		"forge unreadable": {func(h *triggerHarness) { h.heads.err = errors.New("connection refused") }, http.StatusBadGateway},
		"request closed":   {func(h *triggerHarness) { h.heads.head.Open = false }, http.StatusConflict},
		"store unreadable": {func(h *triggerHarness) { h.envs.err = errors.New("disk I/O error") }, http.StatusInternalServerError},
		"queue failure":    {func(h *triggerHarness) { h.q.err = errors.New("disk full") }, http.StatusInternalServerError},
	} {
		h := newTriggerHarness()
		tc.edit(h)
		rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody)
		if rec.Code != tc.code || h.w.n != 0 || (name != "queue failure" && h.q.recorded() != 0) {
			t.Errorf("%s: reply %d %s, recorded %d; want %d and nothing queued", name, rec.Code, rec.Body, h.q.recorded(), tc.code)
		}
	}
}

// The caller names a project and a number, and nothing else: a commit, a
// branch or a head project in the body is refused.
func TestTriggerRefusesBadBodies(t *testing.T) {
	for name, body := range map[string]string{
		"not json":         `repository=acme/app`,
		"names a commit":   `{"repository":"acme/app","pull_request":7,"commit_sha":"` + headSHA + `"}`,
		"names a branch":   `{"repository":"acme/app","pull_request":7,"ref":"main"}`,
		"no number":        `{"repository":"acme/app"}`,
		"number zero":      `{"repository":"acme/app","pull_request":0}`,
		"negative":         `{"repository":"acme/app","pull_request":-7}`,
		"bad repository":   `{"repository":"../app","pull_request":7}`,
		"gitlab path":      `{"repository":"acme/sub/app","pull_request":7}`,
		"trailing data":    triggerBody + `{}`,
		"two documents":    triggerBody + "\n" + triggerBody,
		"number as string": `{"repository":"acme/app","pull_request":"7"}`,
	} {
		h := newTriggerHarness()
		rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, body)
		if rec.Code != http.StatusBadRequest || h.heads.reads != 0 || h.q.recorded() != 0 {
			t.Errorf("%s: reply %d, forge reads %d, recorded %d", name, rec.Code, h.heads.reads, h.q.recorded())
		}
	}
	h := newTriggerHarness()
	big := `{"repository":"acme/app","pull_request":7,"x":"` + strings.Repeat("a", maxTriggerBody) + `"}`
	if rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: reply %d", rec.Code)
	}
	// Each forge's own grammar.
	h = newTriggerHarness()
	h.cfg.VCSProvider = "gitlab"
	srv, err := NewServer(slog.New(slog.DiscardHandler), h.cfg, []byte(testSecret), h.q, h.w, nil,
		WithProvider(newGLHarness(t).provider), WithTrigger([]byte(triggerToken), h.heads, h.envs))
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(t, srv, http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, `{"repository":"acme/sub/app","pull_request":7}`); rec.Code != http.StatusAccepted {
		t.Errorf("gitlab path under gitlab: reply %d %s", rec.Code, rec.Body)
	}
}

func TestTriggerAndStatusNeedTheToken(t *testing.T) {
	for name, auth := range map[string]string{
		"none":         "",
		"wrong":        "Bearer " + strings.Repeat("f", 64),
		"prefix":       "Bearer " + triggerToken[:63],
		"plus a byte":  "Bearer " + triggerToken + "0",
		"basic scheme": "Basic " + triggerToken,
		"bare token":   triggerToken,
		"lower bearer": "bearer " + triggerToken,
		"the webhook":  "Bearer " + testSecret,
	} {
		h := newTriggerHarness()
		srv := h.server(t)
		for _, rec := range []*httptest.ResponseRecorder{
			call(t, srv, http.MethodPost, "/api/v1/trigger", auth, triggerBody),
			call(t, srv, http.MethodGet, "/api/v1/status/"+triggerEnv, auth, ""),
		} {
			if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), triggerToken) {
				t.Errorf("%s: reply %d %s", name, rec.Code, rec.Body)
			}
		}
		if h.heads.reads != 0 || h.q.recorded() != 0 {
			t.Errorf("%s: forge reads %d, recorded %d", name, h.heads.reads, h.q.recorded())
		}
	}
	// Two Authorization headers are refused, whichever is right.
	h := newTriggerHarness()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trigger", strings.NewReader(triggerBody))
	req.Header.Add("Authorization", "Bearer "+triggerToken)
	req.Header.Add("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.server(t).Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("two headers: reply %d", rec.Code)
	}
}

// Rate limited before authentication: a token is not guessed faster than
// the bucket refills, and a trigger storm queues at most the burst.
func TestTriggerIsRateLimited(t *testing.T) {
	h := newTriggerHarness()
	srv := h.server(t)
	h.envs.envs[triggerEnv] = store.EnvironmentStatus{Latest: store.Job{Type: store.JobDeploy, Status: store.StatusSuccess, Source: store.Source{CommitSHA: headSHA}}}
	for i := range triggerBurst {
		if rec := call(t, srv, http.MethodPost, "/api/v1/trigger", "Bearer wrong", triggerBody); rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: reply %d", i, rec.Code)
		}
	}
	rec := call(t, srv, http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("past the burst: reply %d", rec.Code)
	}
	// The bucket refills with time; status reads have their own.
	h.now = h.now.Add(triggerEvery)
	if rec := call(t, srv, http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody); rec.Code != http.StatusOK {
		t.Errorf("after a refill: reply %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, srv, http.MethodGet, "/api/v1/status/"+triggerEnv, "Bearer "+triggerToken, ""); rec.Code != http.StatusOK {
		t.Errorf("status beside an empty trigger bucket: reply %d", rec.Code)
	}
}

func TestStatusReportsTheEnvironment(t *testing.T) {
	h := newTriggerHarness()
	active := v1Time.Add(-time.Minute)
	h.envs.envs[triggerEnv] = store.EnvironmentStatus{Latest: store.Job{ID: 5, EnvID: triggerEnv, Type: store.JobDeploy, Status: store.StatusSuccess,
		Source: store.Source{CommitSHA: headSHA}}, LastActive: active}
	deploying := envid.Generate("acme/app", "feature/y", 8)
	h.envs.envs[deploying] = store.EnvironmentStatus{Latest: store.Job{ID: 6, EnvID: deploying, Type: store.JobDeploy, Status: store.StatusInProgress}}
	failed := envid.Generate("acme/app", "feature/z", 9)
	h.envs.envs[failed] = store.EnvironmentStatus{Latest: store.Job{ID: 7, EnvID: failed, Type: store.JobDeploy, Status: store.StatusFailed, Failure: store.FailureBuild}}
	srv := h.server(t)

	r := decodeReply(t, call(t, srv, http.MethodGet, "/api/v1/status/"+triggerEnv, "Bearer "+triggerToken, ""))
	if r.State != "running" || r.PreviewURL != "https://"+triggerEnv+".preview.corp" || r.JobID != 5 || r.CommitSHA != headSHA ||
		r.LastActiveAt == nil || !r.LastActiveAt.Equal(active) {
		t.Errorf("running = %+v", r)
	}
	if r := decodeReply(t, call(t, srv, http.MethodGet, "/api/v1/status/"+deploying, "Bearer "+triggerToken, "")); r.State != "deploying" || r.PreviewURL != "" {
		t.Errorf("deploying = %+v; no preview URL until it runs", r)
	}
	if r := decodeReply(t, call(t, srv, http.MethodGet, "/api/v1/status/"+failed, "Bearer "+triggerToken, "")); r.State != "failed" || r.Failure != "build" || r.PreviewURL != "" {
		t.Errorf("failed = %+v", r)
	}
	if rec := call(t, srv, http.MethodGet, "/api/v1/status/"+envid.Generate("x/y", "z", 1), "Bearer "+triggerToken, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown: reply %d", rec.Code)
	}
	for _, bad := range []string{"Pr-1-x", "..", "pr-1-0a0a0a0a0a%0a"} {
		// Refused by the handler, or redirected by the mux to a clean path:
		// never answered.
		if rec := call(t, srv, http.MethodGet, "/api/v1/status/"+bad, "Bearer "+triggerToken, ""); rec.Code == http.StatusOK {
			t.Errorf("%q: reply %d", bad, rec.Code)
		}
	}
}

func TestTriggerServerConfiguration(t *testing.T) {
	h := newTriggerHarness()
	logger := slog.New(slog.DiscardHandler)
	for name, tc := range map[string]struct {
		on   bool
		opts []Option
	}{
		"on without the option": {true, nil},
		"option while off":      {false, []Option{WithTrigger([]byte(triggerToken), h.heads, h.envs)}},
		"short token":           {true, []Option{WithTrigger([]byte("short"), h.heads, h.envs)}},
		"token with a space":    {true, []Option{WithTrigger([]byte(triggerToken[:40]+" "+triggerToken[:10]), h.heads, h.envs)}},
		"no forge":              {true, []Option{WithTrigger([]byte(triggerToken), nil, h.envs)}},
		"no store":              {true, []Option{WithTrigger([]byte(triggerToken), h.heads, nil)}},
	} {
		h.cfg.TriggerAPI = tc.on
		if _, err := NewServer(logger, h.cfg, []byte(testSecret), h.q, h.w, h.gh, tc.opts...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Off: the routes do not exist.
	gh := newHarness()
	srv, err := NewServer(logger, gh.cfg, []byte(testSecret), gh.q, gh.w, gh.gh)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(t, srv, http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody); rec.Code != http.StatusNotFound {
		t.Errorf("trigger route while off: reply %d", rec.Code)
	}
	// The caller may clear its token once WithTrigger returned.
	token := []byte(triggerToken)
	opt := WithTrigger(token, h.heads, h.envs)
	clear(token)
	h.cfg.TriggerAPI = true
	srv, err = NewServer(logger, h.cfg, []byte(testSecret), h.q, h.w, h.gh, opt)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(t, srv, http.MethodGet, "/api/v1/status/"+triggerEnv, "Bearer "+triggerToken, ""); rec.Code == http.StatusUnauthorized {
		t.Error("the token was read after WithTrigger returned")
	}
}

// The trigger routes have their own source filter: the CI runners, not the
// forge.
func TestTriggerSourceFilter(t *testing.T) {
	h := newTriggerHarness()
	h.cfg.TriggerAllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h.cfg.WebhookAllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	srv := h.server(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trigger", strings.NewReader(triggerBody))
	req.RemoteAddr = "192.0.2.1:4444" // a forge address, not a runner
	req.Header.Set("Authorization", "Bearer "+triggerToken)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || h.q.recorded() != 0 {
		t.Errorf("forge address on the trigger: reply %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/trigger", strings.NewReader(triggerBody))
	req.RemoteAddr = "10.1.2.3:4444"
	req.Header.Set("Authorization", "Bearer "+triggerToken)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Errorf("runner address: reply %d %s", rec.Code, rec.Body)
	}
}

func callFrom(t *testing.T, srv *Server, peer, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/trigger", strings.NewReader(triggerBody))
	req.RemoteAddr = peer
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// The allowance is per peer: a stranger that floods the API with bad tokens
// drains its own bucket, not the CI runner's.
func TestTriggerRateLimitIsPerPeer(t *testing.T) {
	h := newTriggerHarness()
	srv := h.server(t)
	for i := range triggerBurst {
		if rec := callFrom(t, srv, "198.51.100.9:4000", "Bearer wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("stranger, request %d: reply %d", i, rec.Code)
		}
	}
	if rec := callFrom(t, srv, "198.51.100.9:4001", "Bearer wrong"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("stranger past the burst: reply %d", rec.Code)
	}
	// The same host over IPv4-mapped IPv6, and with another source port, is
	// the same peer.
	if rec := callFrom(t, srv, "[::ffff:198.51.100.9]:4002", "Bearer "+triggerToken); rec.Code != http.StatusTooManyRequests {
		t.Errorf("the stranger as an IPv4-mapped address: reply %d", rec.Code)
	}
	// The runner is untouched.
	if rec := callFrom(t, srv, "10.1.2.3:4444", "Bearer "+triggerToken); rec.Code != http.StatusAccepted {
		t.Errorf("runner beside a flooding stranger: reply %d %s", rec.Code, rec.Body)
	}
	// A peer that is not an address shares one bucket and cannot dodge the limit.
	for range triggerBurst {
		callFrom(t, srv, "not-an-address", "Bearer wrong")
	}
	if rec := callFrom(t, srv, "also-not-one", "Bearer wrong"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("unreadable peers: reply %d", rec.Code)
	}
}

// The table of peers is bounded and fails closed: when every remembered peer
// is still drained, a new one is refused until a bucket refills.
func TestPeerLimiterIsBoundedAndFailsClosed(t *testing.T) {
	l := newPeerLimiter(1, time.Second)
	now := v1Time
	peer := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	for i := range maxLimitedPeers {
		if !l.take(peer(i), now) {
			t.Fatalf("peer %d refused", i)
		}
	}
	if len(l.peers) != maxLimitedPeers {
		t.Fatalf("%d peers remembered", len(l.peers))
	}
	if l.take(peer(maxLimitedPeers), now) {
		t.Error("a new peer was accepted with the table full of drained peers")
	}
	if l.take(peer(0), now) {
		t.Error("a drained peer was accepted again before its refill")
	}
	// After a refill the idle peers are forgotten and a new one fits.
	now = now.Add(time.Second)
	if !l.take(peer(maxLimitedPeers), now) {
		t.Error("a new peer was refused although every bucket was full again")
	}
	if len(l.peers) > maxLimitedPeers {
		t.Errorf("%d peers remembered, bound %d", len(l.peers), maxLimitedPeers)
	}
}

// The intent is ordered by the instant it was received, before the forge is
// read: a close that lands while the forge answers is ordered after it.
func TestTriggerIsOrderedBeforeTheForgeIsRead(t *testing.T) {
	h := newTriggerHarness()
	h.heads.onRead = func() { h.now = h.now.Add(3 * time.Second) } // the forge is slow, or the PR closes
	rec := call(t, h.server(t), http.MethodPost, "/api/v1/trigger", "Bearer "+triggerToken, triggerBody)
	if rec.Code != http.StatusAccepted || len(h.q.got) != 1 {
		t.Fatalf("reply %d %s, deliveries %d", rec.Code, rec.Body, len(h.q.got))
	}
	if d := h.q.got[0]; d.Seq != validate.SeqAt(v1Time) || !d.ReceivedAt.Equal(v1Time) {
		t.Errorf("ordered at %v (seq %d), want the instant before the forge read, %v", d.ReceivedAt, d.Seq, v1Time)
	}
}

// The source filter names what it refused and the setting that holds the
// allowed addresses: the trigger's, not the webhook's.
func TestTriggerSourceFilterNamesItsOwnSetting(t *testing.T) {
	h := newTriggerHarness()
	h.cfg.TriggerAllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	var logs strings.Builder
	srv, err := NewServer(slog.New(slog.NewTextHandler(&logs, nil)), h.cfg, []byte(testSecret), h.q, h.w, h.gh,
		WithTrigger([]byte(triggerToken), h.heads, h.envs))
	if err != nil {
		t.Fatal(err)
	}
	if rec := callFrom(t, srv, "192.0.2.1:4444", "Bearer "+triggerToken); rec.Code != http.StatusForbidden {
		t.Fatalf("reply %d", rec.Code)
	}
	if got := logs.String(); !strings.Contains(got, "Trigger API request refused: source outside PREVIEWD_TRIGGER_ALLOWED_CIDRS") || strings.Contains(got, "WEBHOOK") {
		t.Errorf("log = %q", got)
	}
}
