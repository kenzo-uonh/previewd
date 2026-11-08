package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	fjSecret   = "forgejo-hook-secret"
	fjUUID     = "8f14e45f-ceea-467a-9575-4c5b0b5b2e6c"
	fjRepo     = "acme.corp/app"
	fjCloneURL = "https://forge.corp/acme.corp/app.git"
)

var (
	fjEnv = envid.Generate(fjRepo, "feature/x", 7)
	// fjSubmitted is the submission Forgejo reports for the test approval:
	// 24 s before v1Time, inside the V1-I7 window.
	fjSubmitted = time.Date(2014, 4, 25, 12, 52, 0, 0, time.UTC)
)

// fjBody is a Forgejo pull request delivery for acme.corp/app#7 by sender.
func fjBody(t *testing.T, action string, sender int64, login string, edit func(doc map[string]any)) string {
	t.Helper()
	doc := map[string]any{
		"action": action, "number": 7,
		"pull_request": map[string]any{
			"number": 7, "user": map[string]any{"id": 4242, "login": "forker"},
			"head":       map[string]any{"ref": "feature/x", "sha": headSHA, "repo": map[string]any{"full_name": "forker/app"}},
			"updated_at": signedAt,
		},
		"repository": map[string]any{"full_name": fjRepo, "clone_url": fjCloneURL},
		"sender":     map[string]any{"id": sender, "login": login},
	}
	if edit != nil {
		edit(doc)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fjReviewBody(t *testing.T, review string, sender int64, login string) string {
	return fjBody(t, "reviewed", sender, login, func(d map[string]any) {
		d["review"] = map[string]any{"type": review, "content": "LGTM"}
	})
}

// fjDriver is the Forgejo the handler reads: the real driver authenticates
// and decodes, the pull request and its reviews are as the test sets them.
type fjDriver struct {
	vcs.Provider
	state      vcs.MRState
	stateErr   error
	reviews    []vcs.ReviewState
	reviewsErr error
	reads      []string
}

func (f *fjDriver) GetMRState(_ context.Context, projectID, mrIID string) (*vcs.MRState, error) {
	f.reads = append(f.reads, "pr "+projectID+"#"+mrIID)
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	st := f.state
	return &st, nil
}

func (f *fjDriver) Reviews(_ context.Context, repo string, number uint32) ([]vcs.ReviewState, error) {
	f.reads = append(f.reads, "reviews "+repo)
	return f.reviews, f.reviewsErr
}

func approval(id, user int64, login, state, commit string) vcs.ReviewState {
	return vcs.ReviewState{ID: id, User: vcs.Account{Login: login, ID: user}, State: state, CommitID: commit, SubmittedAt: fjSubmitted}
}

type fjHarness struct {
	*harness
	driver *fjDriver
}

func newFJHarness(t *testing.T) *fjHarness {
	t.Helper()
	f, err := vcs.NewForgejo(vcs.ForgejoConfig{BaseURL: "https://forge.corp", Token: []byte("fj-TESTONLY")})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness()
	h.cfg.VCSProvider = "forgejo"
	h.cfg.Approvers = map[string][]validate.Approver{fjRepo: {{Login: "lead.dev", ID: 7}}}
	return &fjHarness{harness: h, driver: &fjDriver{
		Provider: f,
		state:    vcs.MRState{Open: true, HeadSHA: headSHA, HeadProject: "forker/app", Author: vcs.Account{Login: "forker", ID: 4242}},
		reviews:  []vcs.ReviewState{approval(31, 7, "lead.dev", "APPROVED", headSHA)},
	}}
}

func (h *fjHarness) server(t *testing.T) *Server {
	t.Helper()
	logs := h.logs
	if logs == nil {
		logs = io.Discard
	}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := NewServer(logger, h.cfg, []byte(fjSecret), h.q, h.w, nil, WithProvider(h.driver), WithReviews(h.driver))
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return h.now }
	return srv
}

func fjSign(body string) string {
	mac := hmac.New(sha256.New, []byte(fjSecret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// send posts a delivery as Forgejo does (both header families); header
// edits the request before it is served.
func (h *fjHarness) send(t *testing.T, event, body string, header func(http.Header)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/forgejo", strings.NewReader(body))
	req.Header.Set("X-Forgejo-Signature", fjSign(body))
	req.Header.Set("X-Gitea-Signature", fjSign(body))
	req.Header.Set("X-Forgejo-Event", event)
	req.Header.Set("X-Gitea-Event", event)
	req.Header.Set("X-Forgejo-Delivery", fjUUID)
	req.Header.Set("X-Gitea-Delivery", fjUUID)
	if header != nil {
		header(req.Header)
	}
	rec := httptest.NewRecorder()
	h.server(t).Routes().ServeHTTP(rec, req)
	return rec
}

func TestForgejoWebhookQueuesDeployAndTeardown(t *testing.T) {
	for action, typ := range map[string]store.JobType{
		"opened": store.JobDeploy, "reopened": store.JobDeploy, "synchronized": store.JobDeploy, "closed": store.JobTeardown,
	} {
		t.Run(action, func(t *testing.T) {
			h := newFJHarness(t)
			body := fjBody(t, action, 99, "pusher", nil)
			rec := h.send(t, "pull_request", body, nil)
			if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) || h.w.n != 1 {
				t.Fatalf("reply %d %s, notified %d", rec.Code, rec.Body, h.w.n)
			}
			want := store.Delivery{
				ID: fjUUID, PayloadSHA256: sha(body), EnvID: fjEnv, Type: typ, Seq: validate.SeqAt(v1Time),
				Source: store.Source{Repo: fjRepo, HeadRepo: "forker/app", PRNumber: 7, OpenerLogin: "forker", OpenerID: 4242,
					CommitSHA: headSHA, CloneURL: fjCloneURL},
				ReceivedAt: v1Time,
			}
			if len(h.q.got) != 1 || h.q.got[0] != want {
				t.Fatalf("delivery = %+v\nwant %+v", h.q.got, want)
			}
		})
	}
}

func TestForgejoWebhookRefusesWhatIsNotAuthenticated(t *testing.T) {
	body := func(t *testing.T) string { return fjBody(t, "opened", 99, "pusher", nil) }
	for name, header := range map[string]func(http.Header){
		"no signature": func(h http.Header) { h.Del("X-Forgejo-Signature"); h.Del("X-Gitea-Signature") },
		"wrong":        func(h http.Header) { h.Set("X-Forgejo-Signature", strings.Repeat("0", 64)) },
		"disagree":     func(h http.Header) { h.Set("X-Gitea-Signature", strings.Repeat("0", 64)) },
		"github style": func(h http.Header) {
			h.Del("X-Forgejo-Signature")
			h.Del("X-Gitea-Signature")
			h.Set(validate.SignatureHeader, signature([]byte(fjSecret), []byte("{}")))
		},
	} {
		h := newFJHarness(t)
		rec := h.send(t, "pull_request", body(t), header)
		if rec.Code != http.StatusUnauthorized || h.q.recorded() != 0 || h.w.n != 0 || len(h.driver.reads) != 0 {
			t.Errorf("%s: reply %d, recorded %d, notified %d, reads %v", name, rec.Code, h.q.recorded(), h.w.n, h.driver.reads)
		}
	}
	// Gitea sends its own family only.
	h := newFJHarness(t)
	rec := h.send(t, "pull_request", body(t), func(h http.Header) {
		h.Del("X-Forgejo-Signature")
		h.Del("X-Forgejo-Event")
		h.Del("X-Forgejo-Delivery")
	})
	if rec.Code != http.StatusAccepted || len(h.q.got) != 1 {
		t.Errorf("gitea headers: reply %d %s", rec.Code, rec.Body)
	}
}

func TestForgejoWebhookHeaders(t *testing.T) {
	body := func(t *testing.T) string { return fjBody(t, "opened", 99, "pusher", nil) }
	for name, header := range map[string]func(http.Header){
		"no event":        func(h http.Header) { h.Del("X-Forgejo-Event"); h.Del("X-Gitea-Event") },
		"events disagree": func(h http.Header) { h.Set("X-Gitea-Event", "push") },
		"event twice":     func(h http.Header) { h.Add("X-Forgejo-Event", "pull_request") },
		"no delivery":     func(h http.Header) { h.Del("X-Forgejo-Delivery"); h.Del("X-Gitea-Delivery") },
		"bad delivery": func(h http.Header) {
			h.Set("X-Forgejo-Delivery", "delivery-1")
			h.Set("X-Gitea-Delivery", "delivery-1")
		},
		"deliveries differ": func(h http.Header) { h.Set("X-Gitea-Delivery", "0f14e45f-ceea-467a-9575-4c5b0b5b2e6c") },
	} {
		h := newFJHarness(t)
		if rec := h.send(t, "pull_request", body(t), header); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
			t.Errorf("%s: reply %d %s, recorded %d", name, rec.Code, rec.Body, h.q.recorded())
		}
	}

	for _, event := range []string{"push", "issues", "issue_comment", "pull_request_comment", "create", "Pull_Request"} {
		h := newFJHarness(t)
		rec := h.send(t, event, body(t), nil)
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"ignored"`) || h.q.recorded() != 0 {
			t.Errorf("%s: reply %d %s, recorded %d", event, rec.Code, rec.Body, h.q.recorded())
		}
	}

	h := newFJHarness(t)
	h.send(t, "pull_request", body(t), func(h http.Header) {
		h.Set("X-Forgejo-Delivery", strings.ToUpper(fjUUID))
		h.Set("X-Gitea-Delivery", strings.ToUpper(fjUUID))
	})
	if len(h.q.got) != 1 || h.q.got[0].ID != fjUUID {
		t.Errorf("deliveries %+v; want the lower-case UUID", h.q.got)
	}
}

// The event header is not signed: it must tell the event the signed body
// tells, or the delivery is refused.
func TestForgejoWebhookHeaderMustMatchTheBody(t *testing.T) {
	for name, tc := range map[string]struct{ event, body string }{
		"review sent as a pull request": {"pull_request", fjReviewBody(t, "pull_request_review_approved", 7, "lead.dev")},
		"push sent as an approval":      {"pull_request_approved", fjBody(t, "synchronized", 7, "lead.dev", nil)},
		"rejection sent as an approval": {"pull_request_approved", fjReviewBody(t, "pull_request_review_rejected", 7, "lead.dev")},
	} {
		h := newFJHarness(t)
		if rec := h.send(t, tc.event, tc.body, nil); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
			t.Errorf("%s: reply %d %s, recorded %d", name, rec.Code, rec.Body, h.q.recorded())
		}
	}
}

func TestForgejoWebhookIgnoresLabelsAndRejectsBadPayloads(t *testing.T) {
	h := newFJHarness(t)
	rec := h.send(t, "pull_request", fjBody(t, "label_updated", 7, "lead.dev", nil), nil)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"action_ignored"`) || h.q.recorded() != 0 {
		t.Errorf("label: reply %d %s, recorded %d", rec.Code, rec.Body, h.q.recorded())
	}
	h = newFJHarness(t)
	if rec := h.send(t, "pull_request", `{"action":"opened"}`, nil); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Errorf("incomplete payload: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
}

// An approver's approval is a grant of the review Forgejo reports for it:
// its ID, its commit, the approver's account ID.
func TestForgejoApprovalIsBoundToTheReview(t *testing.T) {
	h := newFJHarness(t)
	body := fjReviewBody(t, "pull_request_review_approved", 7, "lead.dev")
	rec := h.send(t, "pull_request_approved", body, nil)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) || h.w.n != 1 {
		t.Fatalf("reply %d %s, notified %d", rec.Code, rec.Body, h.w.n)
	}
	want := store.Grant{
		DeliveryID: fjUUID, PayloadSHA256: sha(body), EnvID: fjEnv,
		Source: store.Source{Repo: fjRepo, HeadRepo: "forker/app", PRNumber: 7, OpenerLogin: "forker", OpenerID: 4242,
			CommitSHA: headSHA, CloneURL: fjCloneURL},
		Seq: validate.SeqAt(v1Time), ApproverLogin: "lead.dev", ApproverID: 7, Via: store.ApprovalViaReview, ReviewID: 31,
		Trusted: false, OpenHead: true,
	}
	if len(h.q.grants) != 1 || h.q.grants[0] != want {
		t.Fatalf("grants = %+v\nwant     %+v", h.q.grants, want)
	}
	if a := h.q.audits[0]; a.Kind != store.AuditApprovalGranted || a.Detail != "review" || a.ActorID != 7 || a.ActorLogin != "lead.dev" {
		t.Errorf("audit = %+v", a)
	}
	if got := strings.Join(h.driver.reads, ","); got != "reviews acme.corp/app,pr acme.corp/app#7" {
		t.Errorf("reads %s", got)
	}
}

func TestForgejoApprovalFailsClosed(t *testing.T) {
	approved := approval(31, 7, "lead.dev", "APPROVED", headSHA)
	for name, tc := range map[string]struct {
		sender  int64
		login   string
		edit    func(*fjDriver)
		body    func(map[string]any)
		code    int
		status  string
		reviews bool // the reviews were read
	}{
		"not an approver":     {99, "someone", nil, nil, http.StatusAccepted, "ignored", false},
		"same name, other id": {8, "lead.dev", nil, nil, http.StatusAccepted, "ignored", false},
		"the author":          {7, "lead.dev", nil, func(d map[string]any) { fjPR(d)["user"] = map[string]any{"id": 7, "login": "lead.dev"} }, http.StatusAccepted, "ignored", false},
		"reviews unreadable":  {7, "lead.dev", func(d *fjDriver) { d.reviewsErr = errors.New("connection refused") }, nil, http.StatusServiceUnavailable, "error", true},
		"no review":           {7, "lead.dev", func(d *fjDriver) { d.reviews = nil }, nil, http.StatusAccepted, "ignored", true},
		"latest asks changes": {7, "lead.dev", func(d *fjDriver) {
			d.reviews = append(d.reviews, approval(32, 7, "lead.dev", "CHANGES_REQUESTED", headSHA))
		}, nil, http.StatusAccepted, "ignored", true},
		"latest dismissed":        {7, "lead.dev", func(d *fjDriver) { d.reviews = []vcs.ReviewState{approval(31, 7, "lead.dev", "DISMISSED", headSHA)} }, nil, http.StatusAccepted, "ignored", true},
		"approves another head":   {7, "lead.dev", func(d *fjDriver) { d.reviews = []vcs.ReviewState{approval(31, 7, "lead.dev", "APPROVED", oldSHA)} }, nil, http.StatusAccepted, "ignored", true},
		"someone else's review":   {7, "lead.dev", func(d *fjDriver) { d.reviews = []vcs.ReviewState{approval(31, 8, "other", "APPROVED", headSHA)} }, nil, http.StatusAccepted, "ignored", true},
		"submitted long ago":      {7, "lead.dev", func(d *fjDriver) { d.reviews[0].SubmittedAt = fjSubmitted.Add(-2 * time.Hour) }, nil, http.StatusBadRequest, "", true},
		"no submission time":      {7, "lead.dev", func(d *fjDriver) { d.reviews[0].SubmittedAt = time.Time{} }, nil, http.StatusBadRequest, "", true},
		"submitted in the future": {7, "lead.dev", func(d *fjDriver) { d.reviews[0].SubmittedAt = fjSubmitted.Add(time.Hour) }, nil, http.StatusBadRequest, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newFJHarness(t)
			h.driver.reviews = []vcs.ReviewState{approved}
			if tc.edit != nil {
				tc.edit(h.driver)
			}
			body := fjBody(t, "reviewed", tc.sender, tc.login, func(d map[string]any) {
				d["review"] = map[string]any{"type": "pull_request_review_approved"}
				if tc.body != nil {
					tc.body(d)
				}
			})
			rec := h.send(t, "pull_request_approved", body, nil)
			if rec.Code != tc.code || (tc.status != "" && !strings.Contains(rec.Body.String(), `"status":"`+tc.status+`"`)) {
				t.Errorf("reply %d %s; want %d %s", rec.Code, rec.Body, tc.code, tc.status)
			}
			if h.q.recorded() != 0 || h.w.n != 0 {
				t.Errorf("recorded %d, notified %d; want nothing", h.q.recorded(), h.w.n)
			}
			if read := strings.Contains(strings.Join(h.driver.reads, ","), "reviews"); read != tc.reviews {
				t.Errorf("reviews read %v, want %v", read, tc.reviews)
			}
		})
	}

	// The pull request's state that cannot be read queues no deploy: the
	// grant is recorded without an open head, as on GitHub.
	h := newFJHarness(t)
	h.driver.stateErr = errors.New("connection refused")
	if rec := h.send(t, "pull_request_approved", fjReviewBody(t, "pull_request_review_approved", 7, "lead.dev"), nil); rec.Code != http.StatusAccepted ||
		len(h.q.grants) != 1 || h.q.grants[0].OpenHead || h.q.grants[0].Trusted {
		t.Errorf("unreadable state: reply %d, grants %+v", rec.Code, h.q.grants)
	}
}

func TestForgejoRequestForChangesRevokesTheHead(t *testing.T) {
	h := newFJHarness(t)
	body := fjReviewBody(t, "pull_request_review_rejected", 7, "lead.dev")
	rec := h.send(t, "pull_request_rejected", body, nil)
	if rec.Code != http.StatusAccepted || len(h.q.revokes) != 1 || len(h.q.grants) != 0 {
		t.Fatalf("reply %d %s, revocations %d", rec.Code, rec.Body, len(h.q.revokes))
	}
	want := store.Revoke{DeliveryID: fjUUID, PayloadSHA256: sha(body), EnvID: fjEnv, Repo: fjRepo, PRNumber: 7,
		CommitSHA: headSHA, Seq: validate.SeqAt(v1Time), Reason: store.RevokedChangesRequested}
	if h.q.revokes[0] != want {
		t.Errorf("revocation = %+v\nwant         %+v", h.q.revokes[0], want)
	}
	if strings.Contains(strings.Join(h.driver.reads, ","), "reviews") {
		t.Error("a revocation waited on the reviews")
	}

	// Only an approver's counts; a late one is processed: it only restricts.
	h = newFJHarness(t)
	if rec := h.send(t, "pull_request_rejected", fjReviewBody(t, "pull_request_review_rejected", 99, "someone"), nil); rec.Code != http.StatusAccepted || h.q.recorded() != 0 {
		t.Errorf("stranger: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
	h = newFJHarness(t)
	late := fjBody(t, "reviewed", 7, "lead.dev", func(d map[string]any) {
		d["review"] = map[string]any{"type": "pull_request_review_rejected"}
		fjPR(d)["updated_at"] = "2014-04-25T10:00:00Z"
	})
	if rec := h.send(t, "pull_request_rejected", late, nil); rec.Code != http.StatusAccepted || len(h.q.revokes) != 1 {
		t.Errorf("late rejection: reply %d, revocations %d", rec.Code, len(h.q.revokes))
	}
}

func fjPR(d map[string]any) map[string]any { return d["pull_request"].(map[string]any) }

func TestForgejoServerNeedsItsDriverAndReviews(t *testing.T) {
	h := newFJHarness(t)
	logger := slog.New(slog.DiscardHandler)
	for name, opts := range map[string][]Option{
		"nothing":        nil,
		"no reviews":     {WithProvider(h.driver)},
		"no driver":      {WithReviews(h.driver)},
		"another driver": {WithProvider(newGLHarness(t).provider), WithReviews(h.driver)},
	} {
		if _, err := NewServer(logger, h.cfg, []byte(fjSecret), h.q, h.w, nil, opts...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewServer(logger, h.cfg, nil, h.q, h.w, nil, WithProvider(h.driver), WithReviews(h.driver)); err == nil {
		t.Error("an empty webhook secret was accepted")
	}
}

// One forge per daemon: the others' routes do not exist.
func TestForgejoRoutesOnly(t *testing.T) {
	for _, path := range []string{"/webhooks/github", "/webhooks/gitlab"} {
		h := newFJHarness(t)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.server(t).Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s under forgejo: reply %d", path, rec.Code)
		}
	}
	gh := newHarness()
	srv, err := NewServer(slog.New(slog.DiscardHandler), gh.cfg, []byte(testSecret), gh.q, gh.w, gh.gh)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhooks/forgejo", strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Errorf("forgejo route under github: reply %d", rec.Code)
	}
}
