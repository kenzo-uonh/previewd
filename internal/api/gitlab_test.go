package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

const (
	glSecret   = "gitlab-hook-secret"
	glUUID     = "5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b00"
	glPath     = "acme/sub/app"
	glCloneURL = "https://gitlab.corp/acme/sub/app.git"
	// glSignedAt is 24 s before v1Time, well inside the V1-I7 window.
	glSignedAt = "2014-04-25 12:52:00 UTC"
)

var glEnv = envid.Generate(glPath, "feature/x", 7)

// glBody is a Merge Request Hook for acme/sub/app!7 (project 15).
func glBody(t *testing.T, action, updatedAt string, edit func(attrs map[string]any)) string {
	t.Helper()
	attrs := map[string]any{
		"iid": 7, "action": action, "state": "opened", "source_branch": "feature/x", "target_branch": "main",
		"source_project_id": 15, "target_project_id": 15, "author_id": 4242, "updated_at": updatedAt,
		"last_commit": map[string]any{"id": headSHA},
	}
	if action == "update" {
		attrs["oldrev"] = oldSHA
	}
	if edit != nil {
		edit(attrs)
	}
	b, err := json.Marshal(map[string]any{
		"object_kind": "merge_request", "user": map[string]any{"id": 99, "username": "pusher.dev"},
		"project":           map[string]any{"id": 15, "path_with_namespace": glPath, "git_http_url": glCloneURL},
		"object_attributes": attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// glHarness is a server for the gitlab provider.
type glHarness struct {
	*harness
	provider vcs.Provider
}

func newGLHarness(t *testing.T) *glHarness {
	t.Helper()
	g, err := vcs.NewGitLab(vcs.GitLabConfig{BaseURL: "https://gitlab.corp", Token: []byte("glpat-TESTONLY")})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness()
	h.cfg.VCSProvider = "gitlab"
	h.cfg.Approvers = map[string][]validate.Approver{glPath: {{Login: "lead.dev", ID: 7}}}
	return &glHarness{harness: h, provider: g}
}

func (h *glHarness) server(t *testing.T) *Server {
	t.Helper()
	logs := h.logs
	if logs == nil {
		logs = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := NewServer(logger, h.cfg, []byte(glSecret), h.q, h.w, nil, WithProvider(h.provider))
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return h.now }
	return srv
}

// send posts a hook; header edits the request before it is served.
func (h *glHarness) send(t *testing.T, body string, header func(http.Header)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/gitlab", strings.NewReader(body))
	req.Header.Set("X-Gitlab-Token", glSecret)
	req.Header.Set("X-Gitlab-Event", vcs.EventMergeRequestHook)
	req.Header.Set("X-Gitlab-Event-UUID", glUUID)
	if header != nil {
		header(req.Header)
	}
	rec := httptest.NewRecorder()
	h.server(t).Routes().ServeHTTP(rec, req)
	return rec
}

func TestGitLabWebhookQueuesDeployAndTeardown(t *testing.T) {
	for _, tc := range []struct {
		action string
		typ    store.JobType
	}{
		{"open", store.JobDeploy}, {"reopen", store.JobDeploy}, {"update", store.JobDeploy},
		{"close", store.JobTeardown}, {"merge", store.JobTeardown},
	} {
		t.Run(tc.action, func(t *testing.T) {
			h := newGLHarness(t)
			body := glBody(t, tc.action, glSignedAt, nil)
			rec := h.send(t, body, nil)
			if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) {
				t.Fatalf("reply %d %s", rec.Code, rec.Body)
			}
			if len(h.q.got) != 1 || h.w.n != 1 {
				t.Fatalf("enqueued %d, notified %d", len(h.q.got), h.w.n)
			}
			want := store.Delivery{
				ID: glUUID, PayloadSHA256: sha(body), EnvID: glEnv, Type: tc.typ, Seq: validate.SeqAt(v1Time),
				Source: store.Source{Repo: glPath, HeadRepo: glPath, PRNumber: 7, OpenerLogin: "gitlab-user-4242", OpenerID: 4242,
					CommitSHA: headSHA, CloneURL: glCloneURL},
				ReceivedAt: v1Time,
			}
			if h.q.got[0] != want {
				t.Fatalf("delivery = %+v\nwant %+v", h.q.got[0], want)
			}
		})
	}
}

// A fork: the head lives in another project.
func TestGitLabWebhookRecordsTheForkHead(t *testing.T) {
	h := newGLHarness(t)
	body := glBody(t, "open", glSignedAt, func(a map[string]any) {
		a["source_project_id"] = 88
		a["source"] = map[string]any{"path_with_namespace": "fork/app", "git_http_url": "https://gitlab.corp/fork/app.git"}
	})
	if rec := h.send(t, body, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("reply %d %s", rec.Code, rec.Body)
	}
	if got := h.q.got[0].Source; got.Repo != glPath || got.HeadRepo != "fork/app" {
		t.Errorf("source = %+v", got)
	}
}

func TestGitLabWebhookRefusesWhatIsNotAuthenticated(t *testing.T) {
	for name, header := range map[string]func(http.Header){
		"no token":    func(h http.Header) { h.Del("X-Gitlab-Token") },
		"wrong token": func(h http.Header) { h.Set("X-Gitlab-Token", "guess") },
		"two tokens":  func(h http.Header) { h.Add("X-Gitlab-Token", glSecret) },
		"github header": func(h http.Header) {
			h.Del("X-Gitlab-Token")
			h.Set(validate.SignatureHeader, signature([]byte(glSecret), []byte("{}")))
		},
	} {
		h := newGLHarness(t)
		rec := h.send(t, glBody(t, "open", glSignedAt, nil), header)
		if rec.Code != http.StatusUnauthorized || h.q.recorded() != 0 || h.w.n != 0 {
			t.Errorf("%s: reply %d, recorded %d, notified %d", name, rec.Code, h.q.recorded(), h.w.n)
		}
		if strings.Contains(rec.Body.String(), glSecret) {
			t.Errorf("%s: the reply echoes the secret", name)
		}
	}

	h := newGLHarness(t)
	big := strings.Repeat("x", validate.MaxPayloadBytes+1)
	if rec := h.send(t, big, nil); rec.Code != http.StatusRequestEntityTooLarge || h.q.recorded() != 0 {
		t.Errorf("oversized body: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
}

// NewServer refuses to start a GitLab deployment with no secret: a hook
// with an empty shared secret would admit anyone.
func TestGitLabServerNeedsASecretAndADriver(t *testing.T) {
	h := newGLHarness(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if _, err := NewServer(logger, h.cfg, nil, h.q, h.w, nil, WithProvider(h.provider)); err == nil {
		t.Error("an empty webhook secret was accepted")
	}
	if _, err := NewServer(logger, h.cfg, []byte(glSecret), h.q, h.w, nil); err == nil {
		t.Error("provider=gitlab without a driver was accepted")
	}
	// A GitHub deployment needs no driver option.
	if _, err := NewServer(logger, newHarness().cfg, []byte(testSecret), h.q, h.w, ghesDown); err != nil {
		t.Errorf("github: %v", err)
	}
}

// One forge per daemon: the other's route does not exist.
func TestWebhookRoutesFollowTheProvider(t *testing.T) {
	h := newGLHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(prBody("opened")))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", signature([]byte(glSecret), []byte(prBody("opened"))))
	req.Header.Set("X-GitHub-Delivery", v1Delivery)
	rec := httptest.NewRecorder()
	h.server(t).Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || h.q.recorded() != 0 {
		t.Errorf("github route under gitlab: reply %d, recorded %d", rec.Code, h.q.recorded())
	}

	gh := newHarness()
	srv, err := NewServer(slog.New(slog.NewJSONHandler(io.Discard, nil)), gh.cfg, []byte(testSecret), gh.q, gh.w, gh.gh)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/webhooks/gitlab", strings.NewReader("{}"))
	req.Header.Set("X-Gitlab-Token", testSecret)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("gitlab route under github: reply %d", rec.Code)
	}
}

func TestGitLabWebhookEventHeader(t *testing.T) {
	h := newGLHarness(t)
	if rec := h.send(t, glBody(t, "open", glSignedAt, nil), func(h http.Header) { h.Del("X-Gitlab-Event") }); rec.Code != http.StatusBadRequest {
		t.Errorf("no event header: reply %d", rec.Code)
	}
	for _, event := range []string{"Push Hook", "Note Hook", "Pipeline Hook", "merge request hook"} {
		h := newGLHarness(t)
		rec := h.send(t, glBody(t, "open", glSignedAt, nil), func(h http.Header) { h.Set("X-Gitlab-Event", event) })
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"ignored"`) || h.q.recorded() != 0 {
			t.Errorf("%s: reply %d %s, recorded %d", event, rec.Code, rec.Body, h.q.recorded())
		}
	}
}

func TestGitLabWebhookRejectsAndIgnoresPayloads(t *testing.T) {
	h := newGLHarness(t)
	if rec := h.send(t, `{"object_kind":"merge_request"}`, nil); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Errorf("incomplete payload: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
	if rec := h.send(t, `not json`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed payload: reply %d", rec.Code)
	}
	// A title edit is not a push.
	if rec := h.send(t, glBody(t, "update", glSignedAt, func(a map[string]any) { delete(a, "oldrev") }), nil); rec.Code != http.StatusAccepted ||
		!strings.Contains(rec.Body.String(), `"status":"action_ignored"`) || h.q.recorded() != 0 {
		t.Errorf("update without oldrev: reply %d %s, recorded %d", rec.Code, rec.Body, h.q.recorded())
	}
}

// The event UUID is the replay key; its absence falls back on the body's
// digest (older GitLab); a malformed one is refused, never hashed around.
func TestGitLabWebhookDeliveryID(t *testing.T) {
	body := func(t *testing.T) string { return glBody(t, "open", glSignedAt, nil) }

	h := newGLHarness(t)
	h.send(t, body(t), func(h http.Header) { h.Set("X-Gitlab-Event-UUID", strings.ToUpper(glUUID)) })
	if h.q.got[0].ID != glUUID {
		t.Errorf("ID = %q, want the lower-case UUID", h.q.got[0].ID)
	}

	h = newGLHarness(t)
	b := body(t)
	if rec := h.send(t, b, func(h http.Header) { h.Del("X-Gitlab-Event-UUID") }); rec.Code != http.StatusAccepted {
		t.Fatalf("no UUID: reply %d %s", rec.Code, rec.Body)
	}
	if got, want := h.q.got[0].ID, "sha256-"+sha(b)[:32]; got != want {
		t.Errorf("ID = %q, want %q", got, want)
	}

	for _, bad := range []string{"not-a-uuid", "", strings.Repeat("a", 200)} {
		h := newGLHarness(t)
		rec := h.send(t, body(t), func(h http.Header) { h.Set("X-Gitlab-Event-UUID", bad) })
		if bad == "" {
			// An empty header is an absent one.
			if rec.Code != http.StatusAccepted {
				t.Errorf("empty UUID: reply %d", rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
			t.Errorf("UUID %q: reply %d, recorded %d", bad, rec.Code, h.q.recorded())
		}
	}
}

func TestGitLabWebhookVerdicts(t *testing.T) {
	for verdict, wantCode := range map[store.Verdict]int{store.VerdictStale: http.StatusAccepted, store.VerdictReplay: http.StatusOK} {
		h := newGLHarness(t)
		h.q.verdict = verdict
		rec := h.send(t, glBody(t, "open", glSignedAt, nil), nil)
		if rec.Code != wantCode || h.w.n != 0 {
			t.Errorf("%s: reply %d (notified %d), want %d without notify", verdict, rec.Code, h.w.n, wantCode)
		}
	}
	h := newGLHarness(t)
	h.q.err = fmt.Errorf("disk full")
	if rec := h.send(t, glBody(t, "open", glSignedAt, nil), nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("store failure: reply %d", rec.Code)
	}
}

// V1-I7: a hook received long after the time its body carries is not a new
// intent to deploy; one that only restricts is processed anyway.
func TestGitLabWebhookSignedWindow(t *testing.T) {
	stale := "2014-04-25 11:00:00 UTC" // 1 h 52 min before v1Time, beyond the 15 min window
	h := newGLHarness(t)
	if rec := h.send(t, glBody(t, "open", stale, nil), nil); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Errorf("late deploy: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
	h = newGLHarness(t)
	if rec := h.send(t, glBody(t, "close", stale, nil), nil); rec.Code != http.StatusAccepted || len(h.q.got) != 1 || h.q.got[0].Type != store.JobTeardown {
		t.Errorf("late teardown: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
	// A body stamped in the future of this host's clock is no better.
	h = newGLHarness(t)
	if rec := h.send(t, glBody(t, "open", "2014-04-25 13:30:00 UTC", nil), nil); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Errorf("early deploy: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
}

// glTruth is the GitLab the handler reads in the step that records an
// approval or a revocation: the merge request as it stands.
type glTruth struct {
	vcs.Provider
	state *vcs.MRState
	err   error
	reads []string
}

func (g *glTruth) GetMRState(_ context.Context, projectID, mrIID string) (*vcs.MRState, error) {
	g.reads = append(g.reads, projectID+"!"+mrIID)
	if g.err != nil {
		return nil, g.err
	}
	st := *g.state
	return &st, nil
}

// withTruth makes the harness's GitLab answer with st.
func (h *glHarness) withTruth(st vcs.MRState) *glTruth {
	t := &glTruth{Provider: h.provider, state: &st}
	h.provider = t
	return t
}

// glBodyBy is glBody as sent by account id (login): who approves, who
// withdraws.
func glBodyBy(t *testing.T, action, updatedAt string, id int64, login string, edit func(attrs map[string]any)) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(glBody(t, action, updatedAt, edit)), &doc); err != nil {
		t.Fatal(err)
	}
	doc["user"] = map[string]any{"id": id, "username": login}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func openHeadState() vcs.MRState {
	return vcs.MRState{Open: true, HeadSHA: headSHA, HeadProject: "88", Author: vcs.Account{Login: "forker", ID: 4242}}
}

// An approver's approval is a grant of the head its hook named, bound to the
// approver's account ID, recorded with GitLab's truth read in the same step.
func TestGitLabApprovalIsRecordedAsAGrantOfTheHead(t *testing.T) {
	for _, action := range []string{"approved", "approval"} {
		h := newGLHarness(t)
		gl := h.withTruth(openHeadState())
		body := glBodyBy(t, action, glSignedAt, 7, "lead.dev", nil)
		rec := h.send(t, body, nil)
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) || h.w.n != 1 {
			t.Fatalf("%s: reply %d %s, notified %d", action, rec.Code, rec.Body, h.w.n)
		}
		if len(h.q.grants) != 1 || len(h.q.got) != 0 || len(h.q.revokes) != 0 {
			t.Fatalf("%s: recorded %d grants, %d deliveries, %d revocations", action, len(h.q.grants), len(h.q.got), len(h.q.revokes))
		}
		want := store.Grant{
			DeliveryID: glUUID, PayloadSHA256: sha(body), EnvID: glEnv,
			Source: store.Source{Repo: glPath, PRNumber: 7, OpenerLogin: "gitlab-user-4242", OpenerID: 4242,
				HeadRepo: glPath, CommitSHA: headSHA, CloneURL: glCloneURL},
			Seq: validate.SeqAt(v1Time), ApproverLogin: "lead.dev", ApproverID: 7, Via: store.ApprovalViaMR, ReviewID: 0,
			Trusted: false, OpenHead: true,
		}
		if h.q.grants[0] != want {
			t.Errorf("%s: grant = %+v\nwant    %+v", action, h.q.grants[0], want)
		}
		if a := h.q.audits[0]; a.Kind != store.AuditApprovalGranted || a.Detail != "approval" || a.ActorID != 7 || a.ActorLogin != "lead.dev" || a.CommitSHA != headSHA {
			t.Errorf("%s: audit = %+v", action, a)
		}
		if len(gl.reads) != 1 || gl.reads[0] != "15!7" {
			t.Errorf("%s: GitLab read %v, want the merge request by project ID", action, gl.reads)
		}
	}
}

// Fails closed: GitLab's truth that cannot be read, or that does not match,
// queues no deploy; AuthorizeDeploy reads it again before anything runs.
func TestGitLabApprovalWithoutTruthQueuesNoDeploy(t *testing.T) {
	moved := openHeadState()
	moved.HeadSHA = oldSHA
	closed := openHeadState()
	closed.Open = false
	for name, tc := range map[string]struct {
		truth func(*glTruth)
	}{
		"unreadable": {func(g *glTruth) { g.err = errors.New("connection refused") }},
		"head moved": {func(g *glTruth) { g.state = &moved }},
		"closed":     {func(g *glTruth) { g.state = &closed }},
	} {
		h := newGLHarness(t)
		tc.truth(h.withTruth(openHeadState()))
		if rec := h.send(t, glBodyBy(t, "approved", glSignedAt, 7, "lead.dev", nil), nil); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: reply %d %s", name, rec.Code, rec.Body)
		}
		if len(h.q.grants) != 1 || h.q.grants[0].OpenHead || h.q.grants[0].Trusted {
			t.Errorf("%s: grants %+v; want one with no open head and not trusted", name, h.q.grants)
		}
	}
}

func TestGitLabApprovalByAnyoneButAnApproverIsIgnored(t *testing.T) {
	for name, tc := range map[string]struct {
		id    int64
		login string
		edit  func(map[string]any)
	}{
		"not in PREVIEWD_APPROVERS": {99, "someone", nil},
		"right name, other account": {8, "lead.dev", nil},
		// Self-approval: GitLab can allow it, GitHub cannot. Never a second pair of eyes.
		"the author": {7, "lead.dev", func(a map[string]any) { a["author_id"] = 7 }},
	} {
		h := newGLHarness(t)
		h.withTruth(openHeadState())
		rec := h.send(t, glBodyBy(t, "approved", glSignedAt, tc.id, tc.login, tc.edit), nil)
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"ignored"`) || h.q.recorded() != 0 || h.w.n != 0 {
			t.Errorf("%s: reply %d %s, recorded %d", name, rec.Code, rec.Body, h.q.recorded())
		}
	}
}

func TestGitLabApproverKeepsTheirIDWhenRenamed(t *testing.T) {
	h := newGLHarness(t)
	h.withTruth(openHeadState())
	long := strings.Repeat("renamed-", 6) // 48 bytes: more than the trail keeps
	rec := h.send(t, glBodyBy(t, "approved", glSignedAt, 7, long, nil), nil)
	if rec.Code != http.StatusAccepted || len(h.q.grants) != 1 {
		t.Fatalf("reply %d %s, grants %d", rec.Code, rec.Body, len(h.q.grants))
	}
	if g := h.q.grants[0]; g.ApproverID != 7 || g.ApproverLogin != "lead.dev" {
		t.Errorf("grant approver %s#%d; want the configured login of account 7", g.ApproverLogin, g.ApproverID)
	}

	h = newGLHarness(t)
	h.withTruth(openHeadState())
	if rec := h.send(t, glBodyBy(t, "approved", glSignedAt, 7, "lead.renamed", nil), nil); rec.Code != http.StatusAccepted ||
		len(h.q.grants) != 1 || h.q.grants[0].ApproverLogin != "lead.renamed" {
		t.Errorf("renamed account: reply %d, grants %+v; want the login GitLab reports", rec.Code, h.q.grants)
	}
}

// V1-I7: an approval received long after the time its body carries is not a
// new grant; a withdrawal is processed anyway, it only restricts.
func TestGitLabApprovalSignedWindow(t *testing.T) {
	stale := "2014-04-25 11:00:00 UTC"
	h := newGLHarness(t)
	h.withTruth(openHeadState())
	if rec := h.send(t, glBodyBy(t, "approved", stale, 7, "lead.dev", nil), nil); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Errorf("late approval: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
	h = newGLHarness(t)
	h.withTruth(openHeadState())
	if rec := h.send(t, glBodyBy(t, "unapproved", stale, 7, "lead.dev", nil), nil); rec.Code != http.StatusAccepted || len(h.q.revokes) != 1 {
		t.Errorf("late withdrawal: reply %d, revocations %d", rec.Code, len(h.q.revokes))
	}
}

func TestGitLabUnapprovalRevokesTheCommit(t *testing.T) {
	for _, action := range []string{"unapproved", "unapproval"} {
		h := newGLHarness(t)
		h.withTruth(openHeadState())
		body := glBodyBy(t, action, glSignedAt, 7, "lead.dev", nil)
		rec := h.send(t, body, nil)
		if rec.Code != http.StatusAccepted || len(h.q.revokes) != 1 || len(h.q.grants) != 0 {
			t.Fatalf("%s: reply %d %s, revocations %d, grants %d", action, rec.Code, rec.Body, len(h.q.revokes), len(h.q.grants))
		}
		want := store.Revoke{DeliveryID: glUUID, PayloadSHA256: sha(body), EnvID: glEnv, Repo: glPath, PRNumber: 7,
			CommitSHA: headSHA, Seq: validate.SeqAt(v1Time), Reason: store.RevokedDismissed}
		if h.q.revokes[0] != want {
			t.Errorf("%s: revocation = %+v\nwant         %+v", action, h.q.revokes[0], want)
		}
		if a := h.q.audits[0]; a.Kind != store.AuditApprovalRevoked || a.Detail != "dismissed" || a.ActorID != 7 {
			t.Errorf("%s: audit = %+v", action, a)
		}
	}

	// Only an approver's withdrawal counts: anyone else's never was a grant.
	h := newGLHarness(t)
	h.withTruth(openHeadState())
	if rec := h.send(t, glBodyBy(t, "unapproved", glSignedAt, 99, "someone", nil), nil); rec.Code != http.StatusAccepted ||
		!strings.Contains(rec.Body.String(), `"status":"ignored"`) || h.q.recorded() != 0 {
		t.Errorf("withdrawal by a stranger: reply %d %s, recorded %d", rec.Code, rec.Body, h.q.recorded())
	}
}

func TestGitLabApprovalReplayIsDuplicate(t *testing.T) {
	h := newGLHarness(t)
	h.withTruth(openHeadState())
	h.q.verdict = store.VerdictReplay
	rec := h.send(t, glBodyBy(t, "approved", glSignedAt, 7, "lead.dev", nil), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"duplicate"`) || h.w.n != 0 {
		t.Errorf("replay: reply %d %s, notified %d", rec.Code, rec.Body, h.w.n)
	}
}

func TestGitLabWebhookSourceFilterOnRoute(t *testing.T) {
	h := newGLHarness(t)
	h.cfg.WebhookAllowedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	req := httptest.NewRequest(http.MethodPost, "/webhooks/gitlab", strings.NewReader(glBody(t, "open", glSignedAt, nil)))
	req.RemoteAddr = "192.0.2.1:4444"
	req.Header.Set("X-Gitlab-Token", glSecret)
	req.Header.Set("X-Gitlab-Event", vcs.EventMergeRequestHook)
	rec := httptest.NewRecorder()
	h.server(t).Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || h.q.recorded() != 0 {
		t.Errorf("reply %d, recorded %d", rec.Code, h.q.recorded())
	}
}
