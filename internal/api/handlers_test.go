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
)

const testSecret = "hook-secret"

// 2014-04-25 12:52:24.582507 UTC (GitHub's documented example delivery).
const v1Delivery = "72d3162e-cc78-11e3-81ab-4c9367dc0958"

var v1Time = time.Date(2014, 4, 25, 12, 52, 24, 582507000, time.UTC)

type fakeQueue struct {
	got     []store.Delivery
	verdict store.Verdict
	err     error
}

func (f *fakeQueue) Enqueue(_ context.Context, d store.Delivery) (store.Verdict, int64, error) {
	f.got = append(f.got, d)
	if f.err != nil {
		return "", 0, f.err
	}
	if f.verdict == store.VerdictAccepted {
		return f.verdict, 42, nil
	}
	return f.verdict, 0, nil
}

type countingWaker struct{ n int }

func (c *countingWaker) Notify() { c.n++ }

func prBody(action string) string {
	return fmt.Sprintf(`{"action":%q,"number":7,"pull_request":{"head":{"ref":"feature/x","sha":"0123456789abcdef0123456789abcdef01234567",`+
		`"repo":{"full_name":"acme/app"}},"user":{"login":"opener","id":4242}},`+
		`"repository":{"full_name":"acme/app","clone_url":"https://git.example.internal/acme/app.git"}}`, action)
}

func serve(t *testing.T, q *fakeQueue, w *countingWaker, now time.Time, delivery, body string) *httptest.ResponseRecorder {
	t.Helper()
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), &config.Config{WebhookSecret: testSecret}, q, w)
	srv.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", signature([]byte(testSecret), []byte(body)))
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestWebhookQueuesDeployAndTeardown(t *testing.T) {
	for action, typ := range map[string]store.JobType{
		"opened": store.JobDeploy, "reopened": store.JobDeploy, "synchronize": store.JobDeploy, "closed": store.JobTeardown,
	} {
		t.Run(action, func(t *testing.T) {
			q, w := &fakeQueue{verdict: store.VerdictAccepted}, &countingWaker{}
			body := prBody(action)
			rec := serve(t, q, w, v1Time, strings.ToUpper(v1Delivery), body)
			if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) {
				t.Fatalf("reply %d %s", rec.Code, rec.Body)
			}
			if len(q.got) != 1 || w.n != 1 {
				t.Fatalf("enqueued %d, notified %d", len(q.got), w.n)
			}
			sum := sha256.Sum256([]byte(body))
			want := store.Delivery{
				ID: v1Delivery, PayloadSHA256: hex.EncodeToString(sum[:]),
				EnvID: envid.Generate("acme/app", "feature/x", 7), Type: typ, Seq: 136177231445825070,
				Source: store.Source{Repo: "acme/app", HeadRepo: "acme/app", PRNumber: 7, OpenerLogin: "opener", OpenerID: 4242,
					CommitSHA: "0123456789abcdef0123456789abcdef01234567", CloneURL: "https://git.example.internal/acme/app.git"},
				ReceivedAt: v1Time,
			}
			if q.got[0] != want {
				t.Fatalf("delivery = %+v\nwant %+v", q.got[0], want)
			}
		})
	}
}

func TestWebhookVerdicts(t *testing.T) {
	for verdict, wantCode := range map[store.Verdict]int{store.VerdictStale: http.StatusAccepted, store.VerdictReplay: http.StatusOK} {
		q, w := &fakeQueue{verdict: verdict}, &countingWaker{}
		rec := serve(t, q, w, v1Time, v1Delivery, prBody("opened"))
		if rec.Code != wantCode || w.n != 0 {
			t.Errorf("%s: reply %d (notified %d), want %d without notify", verdict, rec.Code, w.n, wantCode)
		}
	}
	q, w := &fakeQueue{err: errors.New("disk full")}, &countingWaker{}
	if rec := serve(t, q, w, v1Time, v1Delivery, prBody("opened")); rec.Code != http.StatusInternalServerError || w.n != 0 {
		t.Errorf("queue error: reply %d, notified %d", rec.Code, w.n)
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
			q, w := &fakeQueue{verdict: store.VerdictAccepted}, &countingWaker{}
			rec := serve(t, q, w, tc.now, tc.delivery, prBody("opened"))
			if rec.Code != http.StatusBadRequest || len(q.got) != 0 || w.n != 0 {
				t.Fatalf("reply %d, enqueued %d, notified %d; want 400 and nothing queued", rec.Code, len(q.got), w.n)
			}
		})
	}
	// Within the skew bound, and any time in the past (redeliveries keep
	// their original ID), the delivery is accepted.
	for _, now := range []time.Time{v1Time.Add(-4 * time.Minute), v1Time, v1Time.Add(30 * 24 * time.Hour)} {
		q, w := &fakeQueue{verdict: store.VerdictAccepted}, &countingWaker{}
		if rec := serve(t, q, w, now, v1Delivery, prBody("opened")); rec.Code != http.StatusAccepted {
			t.Errorf("now %v: reply %d, want 202", now, rec.Code)
		}
	}
}

func TestWebhookIgnoresOtherActionsWithoutQueueing(t *testing.T) {
	q, w := &fakeQueue{verdict: store.VerdictAccepted}, &countingWaker{}
	rec := serve(t, q, w, v1Time, v1Delivery, prBody("labeled"))
	if rec.Code != http.StatusAccepted || len(q.got) != 0 || !strings.Contains(rec.Body.String(), "action_ignored") {
		t.Fatalf("reply %d %s, enqueued %d", rec.Code, rec.Body, len(q.got))
	}
}
