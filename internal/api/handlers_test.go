package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	testSecret = "hook-secret"
	headSHA    = "0123456789abcdef0123456789abcdef01234567"
	oldSHA     = "1111111111111111111111111111111111111111"
)

// 2014-04-25 12:52:24.582507 UTC (GitHub's documented example delivery).
const v1Delivery = "72d3162e-cc78-11e3-81ab-4c9367dc0958"

var (
	v1Time = time.Date(2014, 4, 25, 12, 52, 24, 582507000, time.UTC)
	// signedAt is the signed payload time of the test bodies: 24 s before
	// the delivery GUID, well inside the V1-I7 window.
	signedAt = "2014-04-25T12:52:00Z"
	testEnv  = envid.Generate("acme/app", "feature/x", 7)
)

// fakeQueue records what the handler hands the store and answers with
// verdict (job 42 when accepted and job is set).
type fakeQueue struct {
	got     []store.Delivery
	grants  []store.Grant
	revokes []store.Revoke
	audits  []store.AuditEvent
	verdict store.Verdict
	job     bool
	err     error
}

func (f *fakeQueue) answer() (store.Verdict, int64, error) {
	switch {
	case f.err != nil:
		return "", 0, f.err
	case f.verdict == store.VerdictAccepted && f.job:
		return f.verdict, 42, nil
	}
	return f.verdict, 0, nil
}

func (f *fakeQueue) Enqueue(_ context.Context, d store.Delivery) (store.Verdict, int64, error) {
	f.got = append(f.got, d)
	return f.answer()
}

func (f *fakeQueue) Approve(_ context.Context, g store.Grant, _ time.Time, a store.AuditEvent) (store.Verdict, int64, error) {
	f.grants, f.audits = append(f.grants, g), append(f.audits, a)
	return f.answer()
}

func (f *fakeQueue) Revoke(_ context.Context, r store.Revoke, _ time.Time, a store.AuditEvent) (store.Verdict, int64, error) {
	f.revokes, f.audits = append(f.revokes, r), append(f.audits, a)
	return f.answer()
}

func (f *fakeQueue) recorded() int { return len(f.got) + len(f.grants) + len(f.revokes) }

// fakeGitHub is GHES truth.
type fakeGitHub struct {
	pr         vcs.PRState
	permission string
	prErr      error
	permErr    error
}

func (f *fakeGitHub) PullRequest(context.Context, string, uint32) (vcs.PRState, error) {
	return f.pr, f.prErr
}

func (f *fakeGitHub) Permission(context.Context, string, string) (string, error) {
	return f.permission, f.permErr
}

type countingWaker struct{ n int }

func (c *countingWaker) Notify() { c.n++ }

// harness is one server with its fakes.
type harness struct {
	q   *fakeQueue
	w   *countingWaker
	gh  GitHub
	cfg *config.Config
	now time.Time
}

func newHarness() *harness {
	return &harness{
		q: &fakeQueue{verdict: store.VerdictAccepted, job: true}, w: &countingWaker{}, now: v1Time,
		cfg: &config.Config{
			WebhookSecret: testSecret, DeliveryMaxAge: 15 * time.Minute, ApprovalLabel: "previewd-approved",
			Approvers: map[string][]validate.Approver{"acme/app": {{Login: "lead-dev", ID: 7}}},
		},
	}
}

func (h *harness) send(t *testing.T, event, delivery, body string) *httptest.ResponseRecorder {
	t.Helper()
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), h.cfg, h.q, h.w, h.gh)
	srv.now = func() time.Time { return h.now }
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-Hub-Signature-256", signature([]byte(testSecret), []byte(body)))
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// pr is the pull_request object of both event kinds.
func pr(updatedAt string) string {
	return fmt.Sprintf(`{"number":7,"head":{"ref":"feature/x","sha":%q,"repo":{"full_name":"acme/app"}},`+
		`"user":{"login":"opener","id":4242},"updated_at":%q}`, headSHA, updatedAt)
}

const repository = `"repository":{"full_name":"acme/app","clone_url":"https://git.example.internal/acme/app.git"}`

func prBodyAt(action, updatedAt, sender, extra string) string {
	return fmt.Sprintf(`{"action":%q,"number":7,"pull_request":%s,%s,"sender":%s%s}`, action, pr(updatedAt), repository, sender, extra)
}

func prBody(action string) string {
	return prBodyAt(action, signedAt, `{"login":"opener","id":4242}`, "")
}

func sha(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func TestWebhookQueuesDeployAndTeardown(t *testing.T) {
	for action, typ := range map[string]store.JobType{
		"opened": store.JobDeploy, "reopened": store.JobDeploy, "synchronize": store.JobDeploy, "closed": store.JobTeardown,
	} {
		t.Run(action, func(t *testing.T) {
			h := newHarness()
			body := prBody(action)
			rec := h.send(t, "pull_request", strings.ToUpper(v1Delivery), body)
			if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) {
				t.Fatalf("reply %d %s", rec.Code, rec.Body)
			}
			if len(h.q.got) != 1 || h.w.n != 1 {
				t.Fatalf("enqueued %d, notified %d", len(h.q.got), h.w.n)
			}
			want := store.Delivery{
				ID: v1Delivery, PayloadSHA256: sha(body), EnvID: testEnv, Type: typ, Seq: 136177231445825070,
				Source: store.Source{Repo: "acme/app", HeadRepo: "acme/app", PRNumber: 7, OpenerLogin: "opener", OpenerID: 4242,
					CommitSHA: headSHA, CloneURL: "https://git.example.internal/acme/app.git"},
				ReceivedAt: v1Time,
			}
			if h.q.got[0] != want {
				t.Fatalf("delivery = %+v\nwant %+v", h.q.got[0], want)
			}
		})
	}
}

func TestWebhookVerdicts(t *testing.T) {
	for verdict, wantCode := range map[store.Verdict]int{store.VerdictStale: http.StatusAccepted, store.VerdictReplay: http.StatusOK} {
		h := newHarness()
		h.q.verdict = verdict
		rec := h.send(t, "pull_request", v1Delivery, prBody("opened"))
		if rec.Code != wantCode || h.w.n != 0 {
			t.Errorf("%s: reply %d (notified %d), want %d without notify", verdict, rec.Code, h.w.n, wantCode)
		}
	}
	h := newHarness()
	h.q.err = errors.New("disk full")
	if rec := h.send(t, "pull_request", v1Delivery, prBody("opened")); rec.Code != http.StatusInternalServerError || h.w.n != 0 {
		t.Errorf("queue error: reply %d, notified %d", rec.Code, h.w.n)
	}
}

// Fail closed: a delivery that cannot be ordered never reaches the queue.
func TestWebhookRejectsUnorderableDeliveries(t *testing.T) {
	for name, tc := range map[string]struct {
		delivery string
		now      time.Time
	}{
		"missing header":      {"", v1Time},
		"uuid v4":             {"3f1c6b2e-9a7d-4c1b-8e2f-0a1b2c3d4e5f", v1Time},
		"not a uuid":          {"delivery-1", v1Time},
		"six minutes ahead":   {v1Delivery, v1Time.Add(-6 * time.Minute)},
		"one hour ahead":      {v1Delivery, v1Time.Add(-time.Hour)},
		"braces":              {"{" + v1Delivery + "}", v1Time},
		"trailing whitespace": {v1Delivery + " ", v1Time},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			h.now = tc.now
			rec := h.send(t, "pull_request", tc.delivery, prBody("opened"))
			if rec.Code != http.StatusBadRequest || h.q.recorded() != 0 || h.w.n != 0 {
				t.Fatalf("reply %d, recorded %d, notified %d; want 400 and nothing recorded", rec.Code, h.q.recorded(), h.w.n)
			}
		})
	}
	// Within the skew bound, and any time in the past (redeliveries keep
	// their original ID and body), the delivery is accepted.
	for _, now := range []time.Time{v1Time.Add(-4 * time.Minute), v1Time, v1Time.Add(30 * 24 * time.Hour)} {
		h := newHarness()
		h.now = now
		if rec := h.send(t, "pull_request", v1Delivery, prBody("opened")); rec.Code != http.StatusAccepted {
			t.Errorf("now %v: reply %d, want 202", now, rec.Code)
		}
	}
}

func TestWebhookIgnoresOtherActionsAndEvents(t *testing.T) {
	for name, tc := range map[string]struct{ event, body, status string }{
		"edited":                    {"pull_request", prBody("edited"), "action_ignored"},
		"label without the opt-in":  {"pull_request", prBodyAt("labeled", signedAt, approverSender, label("previewd-approved")), "ignored"},
		"issue comment event":       {"issue_comment", `{}`, "ignored"},
		"review comment":            {"pull_request_review", reviewBody("submitted", "commented", 7, headSHA, signedAt), "action_ignored"},
		"review edited":             {"pull_request_review", reviewBody("edited", "approved", 7, headSHA, signedAt), "action_ignored"},
		"review by a non-approver":  {"pull_request_review", reviewBody("submitted", "approved", 99, headSHA, signedAt), "ignored"},
		"dismissal of another's":    {"pull_request_review", reviewBody("dismissed", "dismissed", 99, headSHA, signedAt), "ignored"},
		"changes by a non-approver": {"pull_request_review", reviewBody("submitted", "changes_requested", 99, headSHA, signedAt), "ignored"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			rec := h.send(t, tc.event, v1Delivery, tc.body)
			if rec.Code != http.StatusAccepted || h.q.recorded() != 0 || !strings.Contains(rec.Body.String(), `"status":"`+tc.status+`"`) {
				t.Fatalf("reply %d %s, recorded %d", rec.Code, rec.Body, h.q.recorded())
			}
		})
	}
}

// V1-I7: the delivery GUID's time must lie within [signed - 5 min, signed +
// PREVIEWD_DELIVERY_MAX_AGE] of the signed body's time. A body that would
// deploy or grant is refused outside it; one that only restricts (a
// teardown) is processed. The bounds themselves are inside.
func TestWebhookSignedTimeWindow(t *testing.T) {
	at := func(d time.Duration) string { return v1Time.Add(d).Format(time.RFC3339Nano) }
	for name, tc := range map[string]struct {
		action, updatedAt string
		accepted          bool
	}{
		"deploy, body 15 min older":          {"opened", at(-15 * time.Minute), true},
		"deploy, body 15 min and 1 s older":  {"opened", at(-15*time.Minute - time.Second), false},
		"deploy, body a day older (replay)":  {"synchronize", at(-24 * time.Hour), false},
		"deploy, body 5 min newer":           {"opened", at(5 * time.Minute), true},
		"deploy, body 5 min and 1 s newer":   {"reopened", at(5*time.Minute + time.Second), false},
		"teardown, body a day older":         {"closed", at(-24 * time.Hour), true},
		"teardown, body 10 min newer":        {"closed", at(10 * time.Minute), true},
		"deploy, body and GUID at same time": {"opened", at(0), true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			rec := h.send(t, "pull_request", v1Delivery, prBodyAt(tc.action, tc.updatedAt, `{"login":"opener","id":4242}`, ""))
			if tc.accepted != (rec.Code == http.StatusAccepted) || tc.accepted != (len(h.q.got) == 1) {
				t.Fatalf("reply %d %s, enqueued %d; accepted %v", rec.Code, rec.Body, len(h.q.got), tc.accepted)
			}
			if !tc.accepted && rec.Code != http.StatusBadRequest {
				t.Fatalf("reply %d, want 400", rec.Code)
			}
		})
	}
}
