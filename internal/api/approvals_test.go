package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	approverSender   = `{"login":"lead-dev","id":7}`
	dismisserSender  = `{"login":"maintainer","id":55}`
	strangerSender   = `{"login":"stranger","id":99}`
	approvalLabel    = "previewd-approved"
	reviewSubmitted  = "2014-04-25T12:52:10Z"
	reviewIDApproved = 501
)

func label(name string) string { return fmt.Sprintf(`,"label":{"name":%q}`, name) }

// reviewBody is a pull_request_review event: reviewer 7 is lead-dev, the
// approver of acme/app; any other ID is a stranger. A dismissal is sent by
// a maintainer.
func reviewBody(action, state string, reviewerID int64, commit, updatedAt string) string {
	login, sender := "lead-dev", approverSender
	if reviewerID != 7 {
		login, sender = "stranger", strangerSender
	}
	if action == "dismissed" {
		sender = dismisserSender
	}
	return fmt.Sprintf(`{"action":%q,"review":{"id":%d,"user":{"login":%q,"id":%d},"commit_id":%q,"state":%q,"submitted_at":%q},`+
		`"pull_request":%s,%s,"sender":%s}`, action, reviewIDApproved, login, reviewerID, commit, state, reviewSubmitted,
		pr(updatedAt), repository, sender)
}

// trustedPR and forkPR are GHES truth for acme/app#7 open at its head.
var (
	opener    = vcs.Account{Login: "opener", ID: 4242}
	trustedPR = &fakeGitHub{pr: vcs.PRState{Open: true, HeadSHA: headSHA, HeadRepo: "acme/app", Opener: opener, OpenerPermission: "write"}}
	forkPR    = &fakeGitHub{pr: vcs.PRState{Open: true, HeadSHA: headSHA, HeadRepo: "outside/app", Opener: opener}}
)

// prWith is trustedPR's state with one change.
func prWith(change func(*vcs.PRState)) *fakeGitHub {
	st := trustedPR.pr
	change(&st)
	return &fakeGitHub{pr: st}
}

func wantSource(commit string) store.Source {
	return store.Source{Repo: "acme/app", HeadRepo: "acme/app", PRNumber: 7, OpenerLogin: "opener", OpenerID: 4242,
		CommitSHA: commit, CloneURL: "https://git.example.internal/acme/app.git"}
}

// Row: review submitted, approved, by an approver, on the head commit.
func TestReviewApprovalRecordsGrant(t *testing.T) {
	h := newHarness()
	h.gh = forkPR
	body := reviewBody("submitted", "approved", 7, headSHA, signedAt)
	rec := h.send(t, "pull_request_review", v1Delivery, body)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"queued"`) || h.w.n != 1 {
		t.Fatalf("reply %d %s, notified %d", rec.Code, rec.Body, h.w.n)
	}
	want := store.Grant{
		DeliveryID: v1Delivery, PayloadSHA256: sha(body), EnvID: testEnv, Source: wantSource(headSHA),
		Seq: 136177231445825070, ApproverLogin: "lead-dev", ApproverID: 7, Via: store.ApprovalViaReview,
		ReviewID: reviewIDApproved, Trusted: false, OpenHead: true,
	}
	if len(h.q.grants) != 1 || h.q.grants[0] != want {
		t.Fatalf("grant = %+v\nwant %+v", h.q.grants, want)
	}
	wantAudit := store.AuditEvent{Kind: store.AuditApprovalGranted, EnvID: testEnv, Repo: "acme/app", PRNumber: 7,
		CommitSHA: headSHA, ActorLogin: "lead-dev", ActorID: 7, Detail: "review"}
	if h.q.audits[0] != wantAudit {
		t.Fatalf("audit = %+v\nwant %+v", h.q.audits[0], wantAudit)
	}
}

// The approver is matched on the account ID: a renamed approver still
// approves (and is recorded under the new login); an account that took
// the approver's old login does not.
func TestReviewApproverMatchedOnID(t *testing.T) {
	h := newHarness()
	h.cfg.Approvers["acme/app"][0].Login = "old-name"
	if rec := h.send(t, "pull_request_review", v1Delivery, reviewBody("submitted", "approved", 7, headSHA, signedAt)); rec.Code != http.StatusAccepted ||
		len(h.q.grants) != 1 || h.q.grants[0].ApproverLogin != "lead-dev" {
		t.Fatalf("renamed approver: reply %d, grants %+v", rec.Code, h.q.grants)
	}
	h = newHarness()
	body := strings.Replace(reviewBody("submitted", "approved", 99, headSHA, signedAt), `"login":"stranger","id":99},"commit_id"`,
		`"login":"lead-dev","id":99},"commit_id"`, 1)
	if rec := h.send(t, "pull_request_review", v1Delivery, body); rec.Code != http.StatusAccepted || h.q.recorded() != 0 {
		t.Fatalf("approver's login on another account: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
}

// An approval of a commit that is not the head is never recorded (V1-I3).
func TestReviewApprovalOfOldCommitIgnored(t *testing.T) {
	h := newHarness()
	rec := h.send(t, "pull_request_review", v1Delivery, reviewBody("submitted", "approved", 7, oldSHA, signedAt))
	if rec.Code != http.StatusAccepted || h.q.recorded() != 0 || !strings.Contains(rec.Body.String(), `"ignored"`) {
		t.Fatalf("reply %d %s, recorded %d", rec.Code, rec.Body, h.q.recorded())
	}
}

// V1-I7 on approvals: a review submitted outside the window, or a label set
// outside it, is refused; nothing is recorded.
func TestApprovalOutsideSignedWindowRefused(t *testing.T) {
	old := v1Time.Add(-time.Hour).Format(time.RFC3339)
	review := strings.Replace(reviewBody("submitted", "approved", 7, headSHA, signedAt), reviewSubmitted, old, 1)
	h := newHarness()
	if rec := h.send(t, "pull_request_review", v1Delivery, review); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Fatalf("stale review: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
	h = newHarness()
	h.cfg.LabelApproval = true
	if rec := h.send(t, "pull_request", v1Delivery, prBodyAt("labeled", old, approverSender, label(approvalLabel))); rec.Code != http.StatusBadRequest || h.q.recorded() != 0 {
		t.Fatalf("stale label: reply %d, recorded %d", rec.Code, h.q.recorded())
	}
}

// Rows: change request by an approver, dismissal of an approver's review.
// A revocation is processed even outside the signed window: it only
// restricts. The actor is the reviewer, or who dismissed.
func TestReviewRevocations(t *testing.T) {
	old := v1Time.Add(-time.Hour).Format(time.RFC3339)
	for name, tc := range map[string]struct {
		body   string
		reason store.RevocationReason
		actor  string
		id     int64
	}{
		"changes requested": {reviewBody("submitted", "changes_requested", 7, oldSHA, signedAt), store.RevokedChangesRequested, "lead-dev", 7},
		"dismissed":         {reviewBody("dismissed", "dismissed", 7, oldSHA, signedAt), store.RevokedDismissed, "maintainer", 55},
		"dismissed late":    {reviewBody("dismissed", "dismissed", 7, oldSHA, old), store.RevokedDismissed, "maintainer", 55},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			h.gh = trustedPR
			h.q.job = false
			body := tc.body
			rec := h.send(t, "pull_request_review", v1Delivery, body)
			if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"recorded"`) || h.w.n != 0 {
				t.Fatalf("reply %d %s, notified %d", rec.Code, rec.Body, h.w.n)
			}
			want := store.Revoke{DeliveryID: v1Delivery, PayloadSHA256: sha(body), EnvID: testEnv, Repo: "acme/app", PRNumber: 7,
				CommitSHA: oldSHA, Seq: 136177231445825070, Reason: tc.reason, Trusted: true}
			if len(h.q.revokes) != 1 || h.q.revokes[0] != want {
				t.Fatalf("revoke = %+v\nwant %+v", h.q.revokes, want)
			}
			if a := h.q.audits[0]; a.Kind != store.AuditApprovalRevoked || a.ActorLogin != tc.actor || a.ActorID != tc.id ||
				a.Detail != string(tc.reason) || a.CommitSHA != oldSHA {
				t.Fatalf("audit = %+v", a)
			}
		})
	}
}

// Rows: approval label (opt-in, the configured label only, an approver's)
// and its removal (by anyone).
func TestLabelApproval(t *testing.T) {
	h := newHarness()
	h.cfg.LabelApproval = true
	h.gh = forkPR
	body := prBodyAt("labeled", signedAt, approverSender, label(approvalLabel))
	if rec := h.send(t, "pull_request", v1Delivery, body); rec.Code != http.StatusAccepted || len(h.q.grants) != 1 {
		t.Fatalf("labeled: reply %d %s", rec.Code, rec.Body)
	}
	want := store.Grant{DeliveryID: v1Delivery, PayloadSHA256: sha(body), EnvID: testEnv, Source: wantSource(headSHA),
		Seq: 136177231445825070, ApproverLogin: "lead-dev", ApproverID: 7, Via: store.ApprovalViaLabel, OpenHead: true}
	if h.q.grants[0] != want {
		t.Fatalf("grant = %+v\nwant %+v", h.q.grants[0], want)
	}

	for name, body := range map[string]string{
		"another label":         prBodyAt("labeled", signedAt, approverSender, label("bug")),
		"set by a non-approver": prBodyAt("labeled", signedAt, strangerSender, label(approvalLabel)),
		"another label removed": prBodyAt("unlabeled", signedAt, strangerSender, label("bug")),
	} {
		h := newHarness()
		h.cfg.LabelApproval = true
		if rec := h.send(t, "pull_request", v1Delivery, body); rec.Code != http.StatusAccepted || h.q.recorded() != 0 {
			t.Errorf("%s: reply %d, recorded %d", name, rec.Code, h.q.recorded())
		}
	}

	h = newHarness()
	h.cfg.LabelApproval = true
	body = prBodyAt("unlabeled", v1Time.Add(-time.Hour).Format(time.RFC3339), strangerSender, label(approvalLabel))
	if rec := h.send(t, "pull_request", v1Delivery, body); rec.Code != http.StatusAccepted || len(h.q.revokes) != 1 {
		t.Fatalf("unlabeled: reply %d %s", rec.Code, rec.Body)
	}
	if r, a := h.q.revokes[0], h.q.audits[0]; r.Reason != store.RevokedUnlabeled || r.CommitSHA != headSHA || r.Trusted ||
		a.ActorLogin != "stranger" || a.ActorID != 99 {
		t.Fatalf("revoke %+v, audit %+v", r, a)
	}
}

// GitHub truth fails closed: on any failed read, for a fork, a deleted head
// repository or an opener without write access, the environment is
// untrusted; the commit is the open head only if GHES says so now.
func TestApprovalGitHubTruth(t *testing.T) {
	for name, tc := range map[string]struct {
		gh                GitHub
		trusted, openHead bool
	}{
		"GHES unavailable":  {ghesDown, false, false},
		"fork":              {forkPR, false, true},
		"deleted head repo": {prWith(func(s *vcs.PRState) { s.HeadRepo = ""; s.OpenerPermission = "admin" }), false, true},
		"opener reads only": {prWith(func(s *vcs.PRState) { s.OpenerPermission = "read" }), false, true},
		"opener triages":    {prWith(func(s *vcs.PRState) { s.OpenerPermission = "triage" }), false, true},
		"permission unread": {prWith(func(s *vcs.PRState) { s.OpenerPermission = "" }), false, true},
		"opener writes":     {trustedPR, true, true},
		"opener maintains":  {prWith(func(s *vcs.PRState) { s.OpenerPermission = "maintain" }), true, true},
		"closed":            {prWith(func(s *vcs.PRState) { s.Open = false }), true, false},
		"head moved":        {prWith(func(s *vcs.PRState) { s.HeadSHA = oldSHA }), true, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness()
			h.gh = tc.gh
			h.send(t, "pull_request_review", v1Delivery, reviewBody("submitted", "approved", 7, headSHA, signedAt))
			if len(h.q.grants) != 1 || h.q.grants[0].Trusted != tc.trusted || h.q.grants[0].OpenHead != tc.openHead {
				t.Fatalf("grants %+v, want trusted %v, open head %v", h.q.grants, tc.trusted, tc.openHead)
			}
		})
	}
}

// A replayed approval or revocation is a duplicate (200, no wake-up); a
// store failure is a 500.
func TestApprovalVerdicts(t *testing.T) {
	h := newHarness()
	h.q.verdict = store.VerdictReplay
	if rec := h.send(t, "pull_request_review", v1Delivery, reviewBody("submitted", "approved", 7, headSHA, signedAt)); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"duplicate"`) || h.w.n != 0 {
		t.Fatalf("replay: reply %d %s", rec.Code, rec.Body)
	}
	h = newHarness()
	h.q.err = errors.New("disk full")
	if rec := h.send(t, "pull_request_review", v1Delivery, reviewBody("dismissed", "dismissed", 7, headSHA, signedAt)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error: reply %d", rec.Code)
	}
}
