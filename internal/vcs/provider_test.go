package vcs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// The GitHub App client is a driver of the interface (V1.1 spec 3.1).
var _ Provider = (*Client)(nil)

// signBody is the X-Hub-Signature-256 GitHub sends for body.
func signBody(secret []byte, body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

const ghPullRequestBody = `{
  "action": "synchronize",
  "number": 7,
  "pull_request": {
    "number": 7,
    "head": {"ref": "feature/login", "sha": "0123456789abcdef0123456789abcdef01234567", "repo": {"full_name": "acme/app"}},
    "user": {"login": "opener", "id": 4242},
    "updated_at": "2026-10-08T12:00:00Z"
  },
  "repository": {"full_name": "acme/app", "clone_url": "https://ghes.example/acme/app.git"},
  "sender": {"login": "pusher", "id": 99}
}`

func TestGitHubProviderName(t *testing.T) {
	if got := (&Client{}).Name(); got != "github" {
		t.Errorf("Name() = %q, want github", got)
	}
}

func TestGitHubVerifyWebhook(t *testing.T) {
	secret := []byte("s3cret")
	req := func(body, sig string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(body))
		if sig != "" {
			r.Header.Set(validate.SignatureHeader, sig)
		}
		return r
	}
	c := &Client{}

	got, err := c.VerifyWebhook(req(ghPullRequestBody, signBody(secret, ghPullRequestBody)), secret)
	if err != nil || string(got) != ghPullRequestBody {
		t.Fatalf("VerifyWebhook = %q, %v; want the verified body", got, err)
	}
	for name, r := range map[string]*http.Request{
		"no signature":    req(ghPullRequestBody, ""),
		"wrong signature": req(ghPullRequestBody, signBody([]byte("other"), ghPullRequestBody)),
		"tampered body":   req(ghPullRequestBody+" ", signBody(secret, ghPullRequestBody)),
	} {
		if body, err := c.VerifyWebhook(r, secret); !errors.Is(err, validate.ErrSignature) || body != nil {
			t.Errorf("%s: VerifyWebhook = %q, %v; want ErrSignature and no body", name, body, err)
		}
	}
	if _, err := c.VerifyWebhook(req(ghPullRequestBody, signBody(nil, ghPullRequestBody)), nil); !errors.Is(err, validate.ErrSignature) {
		t.Errorf("empty secret: err = %v, want ErrSignature", err)
	}
	big := strings.Repeat("x", validate.MaxPayloadBytes+1)
	if _, err := c.VerifyWebhook(req(big, signBody(secret, big)), secret); err == nil {
		t.Error("an oversized body was accepted")
	}
}

func TestGitHubParseEvent(t *testing.T) {
	ev, err := (&Client{}).ParseEvent([]byte(ghPullRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	want := Event{
		Action: ActionSynchronize, ProjectID: "acme/app", Project: "acme/app", IID: 7,
		HeadRef: "feature/login", HeadSHA: testHead, HeadProject: "acme/app", CloneURL: "https://ghes.example/acme/app.git",
		Author: Account{Login: "opener", ID: 4242}, Sender: Account{Login: "pusher", ID: 99},
		UpdatedAt: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
	}
	if *ev != want {
		t.Errorf("event = %+v\nwant    %+v", *ev, want)
	}

	ignored := strings.Replace(ghPullRequestBody, `"synchronize"`, `"assigned"`, 1)
	if ev, err := (&Client{}).ParseEvent([]byte(ignored)); !errors.Is(err, validate.ErrIgnoredAction) || ev != nil {
		t.Errorf("unsupported action: %v, %v; want ErrIgnoredAction and no event", ev, err)
	}
	if ev, err := (&Client{}).ParseEvent([]byte(`{"action":`)); !errors.Is(err, validate.ErrPayload) || ev != nil {
		t.Errorf("malformed JSON: %v, %v; want ErrPayload and no event", ev, err)
	}
}

func TestGitHubGetMRState(t *testing.T) {
	f := newFakeGHES(t)
	c := f.client(t, nil)

	st, err := c.GetMRState(context.Background(), testRepo, "7")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Open || !st.Trusted || st.HeadSHA != testHead || st.HeadProject != testRepo ||
		st.Author != (Account{Login: "opener", ID: testOpenerID}) || len(st.Labels) != 1 || st.Labels[0] != "previewd-approved" {
		t.Errorf("state = %+v", st)
	}

	// A fork is never trusted, whatever its opener may do upstream.
	f.prReply = func() any {
		d := prDoc(testRepo, "open")
		d["head"] = map[string]any{"sha": testHead, "repo": map[string]string{"full_name": "fork/app"}}
		return d
	}
	if st, err = c.GetMRState(context.Background(), testRepo, "7"); err != nil || st.Trusted {
		t.Errorf("fork: state = %+v, %v; want untrusted", st, err)
	}

	for _, bad := range []string{"", "0", "-1", "07", "x", "4294967296"} {
		if _, err := c.GetMRState(context.Background(), testRepo, bad); err == nil {
			t.Errorf("GetMRState(%q) accepted", bad)
		}
	}
}

func TestGitHubGetApprovalsKeepsStandingApprovalsOnly(t *testing.T) {
	rv := func(id int64, user int64, state, commit string) ReviewState {
		return ReviewState{ID: id, User: Account{Login: "u", ID: user}, State: state, CommitID: commit}
	}
	const other = "fedcba9876543210fedcba9876543210fedcba98"
	got := standingApprovals([]ReviewState{
		rv(1, 7, "APPROVED", other),             // superseded by user 7's later approval of the head
		rv(2, 7, "APPROVED", testHead),          //
		rv(3, 8, "APPROVED", testHead),          // then withdrawn
		rv(4, 8, "CHANGES_REQUESTED", testHead), //
		rv(5, 9, "APPROVED", testHead),          // a later comment does not withdraw it
		rv(6, 9, "COMMENTED", testHead),         //
		rv(7, 10, "APPROVED", testHead),         // dismissed
		rv(8, 10, "DISMISSED", testHead),        //
		rv(9, 11, "PENDING", testHead),          // never submitted
	})
	want := []Approval{
		{User: Account{Login: "u", ID: 7}, CommitSHA: testHead},
		{User: Account{Login: "u", ID: 9}, CommitSHA: testHead},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("standingApprovals = %+v, want %+v", got, want)
	}
}

func TestGitHubGetApprovals(t *testing.T) {
	f := newFakeGHES(t)
	got, err := f.client(t, nil).GetApprovals(context.Background(), testRepo, "7")
	if err != nil {
		t.Fatal(err)
	}
	// The fake serves five identical APPROVED reviews by user 7.
	if len(got) != 1 || got[0] != (Approval{User: Account{Login: "lead-dev", ID: 7}, CommitSHA: testHead}) {
		t.Errorf("approvals = %+v", got)
	}
}

func TestAuthorized(t *testing.T) {
	approvals := []Approval{
		{User: Account{Login: "lead-dev", ID: 7}},
		{User: Account{Login: "intruder", ID: 8}},
		{User: Account{Login: "renamed-account", ID: 9}},
	}
	approvers := []validate.Approver{{Login: "lead-dev", ID: 7}, {Login: "old-name", ID: 9}, {Login: "intruder", ID: 80}}
	got := Authorized(approvals, approvers)
	// The ID is the identity: a name alone (intruder#8 against #80) counts for
	// nothing, a renamed account (#9) still does.
	if len(got) != 2 || got[0].User.ID != 7 || got[1].User.ID != 9 {
		t.Errorf("Authorized = %+v", got)
	}
	if got := Authorized(approvals, nil); len(got) != 0 {
		t.Errorf("no approvers authorize %+v", got)
	}
}
