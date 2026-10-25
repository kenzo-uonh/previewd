package vcs

import (
	"archive/tar"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// The Forgejo driver is a Provider (V1.2 spec 3.1).
var _ Provider = (*Forgejo)(nil)

const (
	fjToken    = "fj-TESTONLY0123456789abcdef0123456789abcd"
	fjSecret   = "forgejo-hook-secret"
	fjRepo     = "acme.corp/app_v2"
	fjAuthorID = 4242
	fjBotID    = 555 // the account the token acts as
)

// fjSign is the signature Forgejo sends for body: hex, no prefix.
func fjSign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// fjHookBody is a pull_request delivery as Forgejo writes it; edit changes
// the decoded document before it is encoded.
func fjHookBody(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	doc := map[string]any{
		"action": "synchronized",
		"number": 7,
		"pull_request": map[string]any{
			"id": 901, "number": 7, "state": "open",
			"user": map[string]any{"id": fjAuthorID, "login": "john.doe"},
			"head": map[string]any{"ref": "feature/login", "sha": testHead, "repo_id": 12,
				"repo": map[string]any{"full_name": fjRepo, "clone_url": "https://forge.corp/" + fjRepo + ".git"}},
			"base":       map[string]any{"ref": "main", "repo": map[string]any{"full_name": fjRepo}},
			"updated_at": "2026-10-20T12:30:05+02:00",
		},
		"repository": map[string]any{"id": 12, "full_name": fjRepo, "clone_url": "https://forge.corp/" + fjRepo + ".git"},
		"sender":     map[string]any{"id": 99, "login": "pusher_1"},
	}
	if edit != nil {
		edit(doc)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fjPR(doc map[string]any) map[string]any { return doc["pull_request"].(map[string]any) }

func TestForgejoName(t *testing.T) {
	if got := (&Forgejo{}).Name(); got != "forgejo" {
		t.Errorf("Name() = %q, want forgejo", got)
	}
}

func fjHook(body string, headers map[string][]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhooks/forgejo", strings.NewReader(body))
	for k, vs := range headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestForgejoVerifyWebhook(t *testing.T) {
	f := &Forgejo{}
	body := string(fjHookBody(t, nil))
	sig := fjSign(fjSecret, body)

	for name, headers := range map[string]map[string][]string{
		"both headers":      {ForgejoSignatureHeader: {sig}, GiteaSignatureHeader: {sig}},
		"forgejo only":      {ForgejoSignatureHeader: {sig}},
		"gitea only":        {GiteaSignatureHeader: {sig}},
		"github one too":    {ForgejoSignatureHeader: {sig}, validate.SignatureHeader: {"sha256=" + sig}},
		"canonical spelled": {"x-forgejo-signature": {sig}},
	} {
		r := fjHook(body, headers)
		got, err := f.VerifyWebhook(r, []byte(fjSecret))
		if err != nil || string(got) != body {
			t.Fatalf("%s: VerifyWebhook = %q, %v; want the body", name, got, err)
		}
		if again, _ := io.ReadAll(r.Body); string(again) != body {
			t.Errorf("%s: the verified body was not restored for the handler", name)
		}
	}

	other := fjSign("other-secret", body)
	for name, tc := range map[string]struct {
		body    string
		headers map[string][]string
		secret  string
	}{
		"no signature":         {body, nil, fjSecret},
		"github header only":   {body, map[string][]string{validate.SignatureHeader: {"sha256=" + sig}}, fjSecret},
		"wrong secret":         {body, map[string][]string{ForgejoSignatureHeader: {other}}, fjSecret},
		"tampered body":        {body + " ", map[string][]string{ForgejoSignatureHeader: {sig}}, fjSecret},
		"github style prefix":  {body, map[string][]string{ForgejoSignatureHeader: {"sha256=" + sig}}, fjSecret},
		"upper case hex":       {body, map[string][]string{ForgejoSignatureHeader: {strings.ToUpper(sig)}}, fjSecret},
		"short digest":         {body, map[string][]string{ForgejoSignatureHeader: {sig[:62]}}, fjSecret},
		"not hex":              {body, map[string][]string{ForgejoSignatureHeader: {strings.Repeat("g", 64)}}, fjSecret},
		"headers disagree":     {body, map[string][]string{ForgejoSignatureHeader: {sig}, GiteaSignatureHeader: {other}}, fjSecret},
		"headers disagree rev": {body, map[string][]string{ForgejoSignatureHeader: {other}, GiteaSignatureHeader: {sig}}, fjSecret},
		"one header twice":     {body, map[string][]string{ForgejoSignatureHeader: {sig, sig}}, fjSecret},
		"empty secret":         {body, map[string][]string{ForgejoSignatureHeader: {fjSign("", body)}}, ""},
	} {
		got, err := f.VerifyWebhook(fjHook(tc.body, tc.headers), []byte(tc.secret))
		if !errors.Is(err, validate.ErrSignature) || got != nil {
			t.Errorf("%s: VerifyWebhook = %q, %v; want ErrSignature and no body", name, got, err)
		}
		if err != nil && strings.Contains(err.Error(), fjSecret) {
			t.Errorf("%s: the error carries the secret: %v", name, err)
		}
	}

	big := strings.Repeat("x", validate.MaxPayloadBytes+1)
	got, err := f.VerifyWebhook(fjHook(big, map[string][]string{ForgejoSignatureHeader: {fjSign(fjSecret, big)}}), []byte(fjSecret))
	if !errors.Is(err, ErrBodyTooLarge) || got != nil {
		t.Errorf("oversized body: %v; want ErrBodyTooLarge", err)
	}
}

func TestForgejoParseEvent(t *testing.T) {
	f := &Forgejo{}
	ev, err := f.ParseEvent(fjHookBody(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Event{
		Action: ActionSynchronize, ProjectID: fjRepo, Project: fjRepo, IID: 7,
		HeadRef: "feature/login", HeadSHA: testHead, HeadProject: fjRepo, CloneURL: "https://forge.corp/" + fjRepo + ".git",
		Author: Account{Login: "john.doe", ID: fjAuthorID}, Sender: Account{Login: "pusher_1", ID: 99},
		UpdatedAt: time.Date(2026, 10, 20, 10, 30, 5, 0, time.UTC),
	}
	if *ev != want {
		t.Errorf("event = %+v\nwant    %+v", *ev, want)
	}

	for action, want := range map[string]string{
		"opened": ActionOpened, "reopened": ActionReopened, "closed": ActionClosed,
		"synchronized": ActionSynchronize, "synchronize": ActionSynchronize,
	} {
		ev, err := f.ParseEvent(fjHookBody(t, func(d map[string]any) { d["action"] = action }))
		if err != nil || ev.Action != want {
			t.Errorf("%s: %+v, %v; want %s", action, ev, err, want)
		}
	}
	for review, want := range map[string]string{
		"pull_request_review_approved": ActionApproved,
		"pull_request_review_rejected": ActionChangesRequested,
	} {
		ev, err := f.ParseEvent(fjHookBody(t, func(d map[string]any) {
			d["action"] = "reviewed"
			d["review"] = map[string]any{"type": review, "content": "LGTM"}
		}))
		if err != nil || ev.Action != want {
			t.Errorf("%s: %+v, %v; want %s", review, ev, err, want)
		}
	}

	// A deleted fork: no head repository, never the base.
	ev, err = f.ParseEvent(fjHookBody(t, func(d map[string]any) { fjPR(d)["head"].(map[string]any)["repo"] = nil }))
	if err != nil || ev.HeadProject != "" {
		t.Errorf("deleted fork: %+v, %v; want no head project", ev, err)
	}

	for name, edit := range map[string]func(map[string]any){
		"labeled":       func(d map[string]any) { d["action"] = "labeled" },
		"unlabeled":     func(d map[string]any) { d["action"] = "unlabeled" },
		"label_updated": func(d map[string]any) { d["action"] = "label_updated" },
		"label_cleared": func(d map[string]any) { d["action"] = "label_cleared" },
		"edited":        func(d map[string]any) { d["action"] = "edited" },
		"review_requested": func(d map[string]any) {
			d["action"] = "review_requested"
		},
		"comment review": func(d map[string]any) {
			d["action"] = "reviewed"
			d["review"] = map[string]any{"type": "pull_request_review_comment"}
		},
	} {
		if ev, err := f.ParseEvent(fjHookBody(t, edit)); !errors.Is(err, validate.ErrIgnoredAction) || ev != nil {
			t.Errorf("%s: %+v, %v; want ErrIgnoredAction and no event", name, ev, err)
		}
	}
}

func TestForgejoParseEventRejectsMissingAndInvalidFields(t *testing.T) {
	f := &Forgejo{}
	for name, edit := range map[string]func(map[string]any){
		"no action":         func(d map[string]any) { delete(d, "action") },
		"no number":         func(d map[string]any) { delete(d, "number") },
		"no pull request":   func(d map[string]any) { delete(d, "pull_request") },
		"no head sha":       func(d map[string]any) { delete(fjPR(d)["head"].(map[string]any), "sha") },
		"no updated_at":     func(d map[string]any) { delete(fjPR(d), "updated_at") },
		"no author":         func(d map[string]any) { delete(fjPR(d), "user") },
		"no sender":         func(d map[string]any) { delete(d, "sender") },
		"no repository":     func(d map[string]any) { delete(d, "repository") },
		"no clone url":      func(d map[string]any) { delete(d["repository"].(map[string]any), "clone_url") },
		"head repo no name": func(d map[string]any) { fjPR(d)["head"].(map[string]any)["repo"] = map[string]any{} },
		"review no type": func(d map[string]any) {
			d["action"] = "reviewed"
			d["review"] = map[string]any{}
		},
		"zero number":       func(d map[string]any) { d["number"] = 0; fjPR(d)["number"] = 0 },
		"number mismatch":   func(d map[string]any) { fjPR(d)["number"] = 8 },
		"bad repository":    func(d map[string]any) { d["repository"].(map[string]any)["full_name"] = "acme/app.git" },
		"bad head repo":     func(d map[string]any) { fjPR(d)["head"].(map[string]any)["repo"] = map[string]any{"full_name": "../x"} },
		"bad ref":           func(d map[string]any) { fjPR(d)["head"].(map[string]any)["ref"] = "a..b" },
		"short sha":         func(d map[string]any) { fjPR(d)["head"].(map[string]any)["sha"] = "0123456" },
		"bad timestamp":     func(d map[string]any) { fjPR(d)["updated_at"] = "2026-10-20 10:30:05 UTC" },
		"bad author login":  func(d map[string]any) { fjPR(d)["user"] = map[string]any{"id": 1, "login": "x y"} },
		"bad author id":     func(d map[string]any) { fjPR(d)["user"] = map[string]any{"id": 0, "login": "x"} },
		"ghost sender":      func(d map[string]any) { d["sender"] = map[string]any{"id": -1, "login": "Ghost"} },
		"credentials clone": func(d map[string]any) { d["repository"].(map[string]any)["clone_url"] = "https://u:p@forge.corp/x.git" },
	} {
		ev, err := f.ParseEvent(fjHookBody(t, edit))
		if !errors.Is(err, validate.ErrPayload) || ev != nil {
			t.Errorf("%s: %+v, %v; want ErrPayload and no event", name, ev, err)
		}
	}
	if ev, err := f.ParseEvent([]byte(`{"action":`)); !errors.Is(err, validate.ErrPayload) || ev != nil {
		t.Errorf("malformed JSON: %+v, %v", ev, err)
	}
	if ev, err := f.ParseEvent([]byte(strings.Repeat(" ", validate.MaxPayloadBytes+1))); !errors.Is(err, validate.ErrPayload) || ev != nil {
		t.Errorf("oversized: %+v, %v", ev, err)
	}
}

// fjFake is a Forgejo API: every call must carry the token in the
// Authorization header, and nowhere else.
type fjFake struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	calls      []string
	pr         func() any
	permission func(login string) (int, any)
	reviews    []map[string]any
	reviewPage int // the server's page size, 50 when 0
	statuses   []map[string]any
	comments   []*fjFakeComment
	archive    func(w http.ResponseWriter, r *http.Request)
}

type fjFakeComment struct {
	ID     int64
	Body   string
	UserID int64
}

func fjPullDoc(state, head string) map[string]any {
	return map[string]any{
		"number": 7, "state": state,
		"head":   map[string]any{"sha": testHead, "repo": map[string]any{"full_name": head}},
		"base":   map[string]any{"repo": map[string]any{"full_name": fjRepo}},
		"user":   map[string]any{"id": fjAuthorID, "login": "john.doe"},
		"labels": []map[string]any{{"name": "previewd"}, {"name": strings.Repeat("l", 80)}},
	}
}

func fjReview(id, user int64, state, commit string) map[string]any {
	return map[string]any{"id": id, "user": map[string]any{"id": user, "login": "user-" + strconv.FormatInt(user, 10)},
		"state": state, "commit_id": commit, "dismissed": false, "submitted_at": "2026-10-20T10:30:05Z"}
}

func newFJFake(t *testing.T) *fjFake {
	t.Helper()
	f := &fjFake{t: t}
	f.pr = func() any { return fjPullDoc("open", fjRepo) }
	f.permission = func(login string) (int, any) {
		id := map[string]int64{"john.doe": fjAuthorID, "lead.dev": 7}[login]
		return http.StatusOK, map[string]any{"permission": "write", "role_name": "write", "user": map[string]any{"id": id, "login": login}}
	}
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "token "+fjToken || strings.Contains(r.URL.String(), fjToken) ||
				r.Header.Get("PRIVATE-TOKEN") != "" {
				t.Errorf("%s %s: not authenticated by the Authorization token alone", r.Method, r.URL)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
				return
			}
			f.mu.Lock()
			f.calls = append(f.calls, r.Method+" "+r.URL.Path)
			f.mu.Unlock()
			h(w, r)
		}
	}
	base := "/api/v1/repos/acme.corp/app_v2"
	mux.HandleFunc("GET "+base+"/pulls/7", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, f.pr())
	}))
	mux.HandleFunc("GET "+base+"/collaborators/{login}/permission", guard(func(w http.ResponseWriter, r *http.Request) {
		code, body := f.permission(r.PathValue("login"))
		writeJSON(w, code, body)
	}))
	mux.HandleFunc("GET "+base+"/pulls/7/reviews", guard(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if r.URL.Query().Get("limit") != "50" || page < 1 {
			t.Errorf("reviews query %q", r.URL.RawQuery)
		}
		size := f.reviewPage
		if size == 0 {
			size = 50
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for i := (page - 1) * size; i < min(page*size, len(f.reviews)); i++ {
			out = append(out, f.reviews[i])
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /api/v1/user", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": fjBotID, "login": "previewd-bot"})
	}))
	mux.HandleFunc("POST "+base+"/statuses/{sha}", guard(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("status body: %v", err)
		}
		in["sha"] = r.PathValue("sha")
		f.mu.Lock()
		f.statuses = append(f.statuses, in)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": 1})
	}))
	mux.HandleFunc("GET "+base+"/issues/7/comments", guard(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []map[string]any{}
		for _, c := range f.comments {
			out = append(out, map[string]any{"id": c.ID, "body": c.Body, "user": map[string]any{"id": c.UserID}})
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("POST "+base+"/issues/7/comments", guard(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		c := &fjFakeComment{ID: int64(1000 + len(f.comments)), Body: in.Body, UserID: fjBotID}
		f.comments = append(f.comments, c)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": c.ID})
	}))
	mux.HandleFunc("PATCH "+base+"/issues/comments/{id}", guard(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.comments {
			if strconv.FormatInt(c.ID, 10) != r.PathValue("id") {
				continue
			}
			if c.UserID != fjBotID {
				writeJSON(w, http.StatusForbidden, map[string]string{"message": "forbidden"})
				return
			}
			c.Body = in.Body
			writeJSON(w, http.StatusOK, map[string]any{"id": c.ID})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
	}))
	mux.HandleFunc("GET "+base+"/archive/{file}", guard(func(w http.ResponseWriter, r *http.Request) {
		if f.archive == nil {
			t.Errorf("unexpected archive call %s", r.URL)
			return
		}
		f.archive(w, r)
	}))
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fjFake) client(t *testing.T) *Forgejo {
	t.Helper()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	c, err := NewForgejo(ForgejoConfig{BaseURL: f.srv.URL, Token: []byte(fjToken), CAPEM: ca, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fjFake) called() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

func TestForgejoPullRequestAndTrust(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)

	st, err := c.GetMRState(context.Background(), fjRepo, "7")
	if err != nil {
		t.Fatal(err)
	}
	// An invalid label is left out: labels carry no authority on Forgejo.
	if !st.Open || !st.Trusted || st.HeadSHA != testHead || st.HeadProject != fjRepo ||
		st.Author != (Account{Login: "john.doe", ID: fjAuthorID}) || len(st.Labels) != 1 || st.Labels[0] != "previewd" {
		t.Errorf("state = %+v", st)
	}
	if got, want := f.called(), "GET /api/v1/repos/acme.corp/app_v2/pulls/7,GET /api/v1/repos/acme.corp/app_v2/collaborators/john.doe/permission"; got != want {
		t.Errorf("calls %s, want %s", got, want)
	}

	// Forgejo's owner is GitHub's admin; read and none are not trusted.
	for perm, trusted := range map[string]bool{"owner": true, "admin": true, "write": true, "read": false, "none": false} {
		f.permission = func(login string) (int, any) {
			return http.StatusOK, map[string]any{"permission": perm, "user": map[string]any{"id": fjAuthorID, "login": login}}
		}
		if st, err := c.GetMRState(context.Background(), fjRepo, "7"); err != nil || st.Trusted != trusted {
			t.Errorf("permission %s: %+v, %v; want trusted %v", perm, st, err, trusted)
		}
	}

	// A fork or a deleted head is never trusted, and no permission is read.
	for name, head := range map[string]any{"fork": map[string]any{"full_name": "intruder/app_v2"}, "deleted": nil} {
		f.calls = nil
		f.pr = func() any {
			d := fjPullDoc("open", fjRepo)
			d["head"] = map[string]any{"sha": testHead, "repo": head}
			return d
		}
		st, err := c.GetMRState(context.Background(), fjRepo, "7")
		if err != nil || st.Trusted || strings.Contains(f.called(), "permission") {
			t.Errorf("%s: %+v, %v, calls %s; want untrusted without a permission read", name, st, err, f.called())
		}
	}

	f.pr = func() any { return fjPullDoc("closed", fjRepo) }
	if st, err := c.GetMRState(context.Background(), fjRepo, "7"); err != nil || st.Open {
		t.Errorf("closed: %+v, %v", st, err)
	}
}

func TestForgejoPullRequestRefusesInconsistentReplies(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)
	for name, edit := range map[string]func(map[string]any){
		"other number":  func(d map[string]any) { d["number"] = 8 },
		"other base":    func(d map[string]any) { d["base"] = map[string]any{"repo": map[string]any{"full_name": "acme/other"}} },
		"no base":       func(d map[string]any) { delete(d, "base") },
		"unknown state": func(d map[string]any) { d["state"] = "merged" },
		"bad head":      func(d map[string]any) { d["head"].(map[string]any)["sha"] = "HEAD" },
		"bad head repo": func(d map[string]any) { d["head"].(map[string]any)["repo"] = map[string]any{"full_name": "a/b/c"} },
		"no author":     func(d map[string]any) { delete(d, "user") },
	} {
		f.pr = func() any { d := fjPullDoc("open", fjRepo); edit(d); return d }
		if st, err := c.GetMRState(context.Background(), fjRepo, "7"); err == nil {
			t.Errorf("%s: accepted %+v", name, st)
		}
	}

	// The permission must be about the account asked for.
	f.pr = func() any { return fjPullDoc("open", fjRepo) }
	f.permission = func(login string) (int, any) {
		return http.StatusOK, map[string]any{"permission": "admin", "user": map[string]any{"id": 1, "login": login}}
	}
	if _, err := c.GetMRState(context.Background(), fjRepo, "7"); !errors.Is(err, ErrAccountMismatch) {
		t.Errorf("another account's permission: %v, want ErrAccountMismatch", err)
	}
	for name, reply := range map[string]map[string]any{
		"unknown permission": {"permission": "maintain", "user": map[string]any{"id": fjAuthorID}},
		"no permission":      {"user": map[string]any{"id": fjAuthorID}},
	} {
		f.permission = func(string) (int, any) { return http.StatusOK, reply }
		if _, err := c.GetMRState(context.Background(), fjRepo, "7"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A refused read (the token's account is not a repository administrator)
	// is an error, never "not trusted".
	f.permission = func(string) (int, any) { return http.StatusForbidden, map[string]string{"message": "only admins"} }
	if _, err := c.GetMRState(context.Background(), fjRepo, "7"); err == nil {
		t.Error("a 403 permission read was taken for an answer")
	}
}

func TestForgejoPermission(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)
	if p, err := c.Permission(context.Background(), fjRepo, Account{Login: "lead.dev", ID: 7}); err != nil || p != "write" {
		t.Errorf("Permission = %q, %v", p, err)
	}
	if _, err := c.Permission(context.Background(), fjRepo, Account{Login: "lead.dev", ID: 8}); !errors.Is(err, ErrAccountMismatch) {
		t.Errorf("renamed login taken by another account: %v, want ErrAccountMismatch", err)
	}
	f.calls = nil
	for _, who := range []Account{{Login: "", ID: 7}, {Login: "x y", ID: 7}, {Login: "lead.dev", ID: 0}} {
		if _, err := c.Permission(context.Background(), fjRepo, who); err == nil {
			t.Errorf("Permission(%+v) accepted", who)
		}
	}
	if f.called() != "" {
		t.Errorf("invalid accounts reached the API: %s", f.called())
	}
}

func TestForgejoReviews(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)
	const other = "fedcba9876543210fedcba9876543210fedcba98"
	dismissed := fjReview(4, 9, "APPROVED", testHead)
	dismissed["dismissed"] = true
	ghost := fjReview(6, 10, "APPROVED", testHead)
	ghost["user"] = map[string]any{"id": -1, "login": "Ghost"}
	request := fjReview(7, 11, "REQUEST_REVIEW", "")
	f.reviews = []map[string]any{
		fjReview(3, 7, "REQUEST_CHANGES", other), // listed out of order: sorted by ID
		fjReview(2, 7, "APPROVED", other),
		dismissed,
		fjReview(5, 8, "COMMENT", testHead),
		ghost,
		request,
		fjReview(8, 7, "APPROVED", testHead),
		fjReview(9, 12, "PENDING", testHead),
	}
	got, err := c.Reviews(context.Background(), fjRepo, 7)
	if err != nil {
		t.Fatal(err)
	}
	var states []string
	for _, r := range got {
		states = append(states, fmt.Sprintf("%d:%d:%s:%s", r.ID, r.User.ID, r.State, r.CommitID[:4]))
	}
	if want := "2:7:APPROVED:fedc,3:7:CHANGES_REQUESTED:fedc,4:9:DISMISSED:0123,8:7:APPROVED:0123"; strings.Join(states, ",") != want {
		t.Errorf("reviews %s\nwant    %s", strings.Join(states, ","), want)
	}
	approvals, err := c.GetApprovals(context.Background(), fjRepo, "7")
	if err != nil || len(approvals) != 1 || approvals[0] != (Approval{User: Account{Login: "user-7", ID: 7}, CommitSHA: testHead}) {
		t.Errorf("approvals = %+v, %v", approvals, err)
	}
}

// Forgejo serves at most its own page size: the pages are read until one is
// empty, so a server that serves fewer than asked never yields a partial
// list (a change request on page 2 would be lost).
func TestForgejoReviewsReadEveryPage(t *testing.T) {
	f := newFJFake(t)
	f.reviewPage = 2
	for i := range 5 {
		f.reviews = append(f.reviews, fjReview(int64(i+1), int64(100+i), "APPROVED", testHead))
	}
	f.reviews = append(f.reviews, fjReview(6, 100, "REQUEST_CHANGES", testHead))
	approvals, err := f.client(t).GetApprovals(context.Background(), fjRepo, "7")
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 4 {
		t.Errorf("approvals = %+v; want account 100's withdrawn by its change request on page 3", approvals)
	}
	if n := strings.Count(f.called(), "reviews"); n != 4 {
		t.Errorf("%d review pages read, want 4 (three full, one empty)", n)
	}
}

func TestForgejoReviewsFailClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		reviews []map[string]any
		page    int
	}{
		"verdict without commit": {[]map[string]any{fjReview(1, 7, "REQUEST_CHANGES", "")}, 0},
		"verdict bad commit":     {[]map[string]any{fjReview(1, 7, "APPROVED", "HEAD")}, 0},
		"unknown state":          {[]map[string]any{fjReview(1, 7, "MAYBE", testHead)}, 0},
		"no id":                  {[]map[string]any{{"state": "APPROVED"}}, 0},
		"same review twice":      {[]map[string]any{fjReview(1, 7, "APPROVED", testHead), fjReview(1, 7, "APPROVED", testHead)}, 0},
		"bad submitted_at": {[]map[string]any{func() map[string]any {
			r := fjReview(1, 7, "APPROVED", testHead)
			r["submitted_at"] = "yesterday"
			return r
		}()}, 0},
		"more pages than bounded": {func() []map[string]any {
			var out []map[string]any
			for i := range maxForgejoReviewPages + 1 {
				out = append(out, fjReview(int64(i+1), 7, "COMMENT", testHead))
			}
			return out
		}(), 1},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFJFake(t)
			f.reviews, f.reviewPage = tc.reviews, tc.page
			if got, err := f.client(t).Reviews(context.Background(), fjRepo, 7); err == nil {
				t.Errorf("accepted %+v", got)
			}
		})
	}
}

func TestForgejoSetCommitStatus(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)
	if err := c.SetCommitStatus(context.Background(), fjRepo, testHead, StateSuccess, "https://env.preview.corp", "Preview ready"); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"sha": testHead, "state": "success", "target_url": "https://env.preview.corp", "description": "Preview ready", "context": "previewd"}
	if len(f.statuses) != 1 || fmt.Sprint(f.statuses[0]) != fmt.Sprint(want) {
		t.Errorf("statuses = %v, want %v", f.statuses, want)
	}

	f.calls = nil
	for name, call := range map[string]func() error{
		"bad state":  func() error { return c.SetCommitStatus(context.Background(), fjRepo, testHead, "error", "", "x") },
		"bad commit": func() error { return c.SetCommitStatus(context.Background(), fjRepo, "HEAD", StatePending, "", "x") },
		"bad repo":   func() error { return c.SetCommitStatus(context.Background(), "../x", testHead, StatePending, "", "x") },
		"bad url": func() error {
			return c.SetCommitStatus(context.Background(), fjRepo, testHead, StatePending, "javascript:x", "x")
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if f.called() != "" {
		t.Errorf("bad arguments reached the API: %s", f.called())
	}
}

func TestForgejoPostCommentCreatesThenUpdatesInPlace(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)
	// Another account's comment with the marker is never taken for ours.
	f.comments = []*fjFakeComment{{ID: 1, Body: CommentMarker + "\nforged", UserID: 66}}
	first, second := CommentMarker+"\nfirst", CommentMarker+"\nsecond"
	if err := c.PostComment(context.Background(), fjRepo, "7", first); err != nil {
		t.Fatal(err)
	}
	if err := c.PostComment(context.Background(), fjRepo, "7", second); err != nil {
		t.Fatal(err)
	}
	if len(f.comments) != 2 || f.comments[0].Body != CommentMarker+"\nforged" || f.comments[1].Body != second {
		t.Errorf("comments = %+v", f.comments)
	}
	f.calls = nil
	if err := c.PostComment(context.Background(), fjRepo, "7", second); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.called(), "PATCH") || strings.Contains(f.called(), "POST") {
		t.Errorf("an unchanged comment was written: %s", f.called())
	}
	for name, body := range map[string]string{"no marker": "hello", "marker twice": CommentMarker + "\n" + CommentMarker} {
		if err := c.PostComment(context.Background(), fjRepo, "7", body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := c.PostComment(context.Background(), fjRepo, "0", first); err == nil {
		t.Error("PR 0 accepted")
	}
}

func TestForgejoFetchTarball(t *testing.T) {
	f := newFJFake(t)
	body := archive(t, testHead, file("Dockerfile", "FROM scratch\n"),
		entry{name: "run.sh", body: "#!/bin/sh\n", typ: tar.TypeReg, mode: 0o755})
	var path string
	f.archive = func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
	dest := filepath.Join(t.TempDir(), "src")
	fetcher, err := NewForgejoFetcher(f.client(t), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := fetcher.Fetch(context.Background(), fjRepo, "https://ignored.example/x.git", testHead, dest); err != nil {
		t.Fatal(err)
	}
	if path != "/api/v1/repos/acme.corp/app_v2/archive/"+testHead+".tar.gz" {
		t.Errorf("archive path %q", path)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "Dockerfile")); err != nil || string(got) != "FROM scratch\n" {
		t.Errorf("Dockerfile = %q, %v", got, err)
	}
}

func TestForgejoFetchTarballRefuses(t *testing.T) {
	const other = "fedcba9876543210fedcba9876543210fedcba98"
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the token followed a redirect to another host")
		}
	}))
	t.Cleanup(redirect.Close)
	for name, tc := range map[string]struct {
		serve    func(w http.ResponseWriter, r *http.Request)
		maxBytes int64
	}{
		"another commit": {func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(archive(t, other, file("Dockerfile", "FROM scratch\n")))
		}, 1 << 20},
		"no commit header": {func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(archive(t, "", file("Dockerfile", "FROM scratch\n")))
		}, 1 << 20},
		"escaping entry": {func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(archive(t, testHead, entry{name: "../evil", body: "x", typ: tar.TypeReg, raw: true}))
		}, 1 << 20},
		"above the cap": {func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(archive(t, testHead, file("big", strings.Repeat("x", 4096))))
		}, 64},
		"redirect": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirect.URL+"/archive.tar.gz", http.StatusFound)
		}, 1 << 20},
		"not found": {func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, 1 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFJFake(t)
			f.archive = tc.serve
			err := f.client(t).FetchTarball(context.Background(), fjRepo, testHead, filepath.Join(t.TempDir(), "src"), tc.maxBytes)
			if err == nil || strings.Contains(err.Error(), fjToken) {
				t.Errorf("FetchTarball = %v; want a refusal without the token", err)
			}
		})
	}

	c := newFJFake(t).client(t)
	for name, call := range map[string]func() error{
		"bad repo":   func() error { return c.FetchTarball(context.Background(), "a/b/c", testHead, t.TempDir()+"/x", 1) },
		"bad commit": func() error { return c.FetchTarball(context.Background(), fjRepo, "main", t.TempDir()+"/x", 1) },
		"no cap":     func() error { return c.FetchTarball(context.Background(), fjRepo, testHead, t.TempDir()+"/x", 0) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewForgejoFetcher(nil, 1); err == nil {
		t.Error("a fetcher without a driver was built")
	}
}

// The API follows no redirect (the token would be carried along) and bounds
// every reply; an error never quotes the token.
func TestForgejoFollowsNoRedirectAndBoundsReplies(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("followed a redirect to %s with Authorization %q", r.URL, r.Header.Get("Authorization"))
	}))
	t.Cleanup(other.Close)
	f := newFJFake(t)
	f.pr = func() any { return map[string]any{"padding": strings.Repeat("x", maxPRReplyBytes)} }
	if _, err := f.client(t).GetMRState(context.Background(), fjRepo, "7"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversized reply: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := NewForgejo(ForgejoConfig{BaseURL: srv.URL, Token: []byte(fjToken), CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetMRState(context.Background(), fjRepo, "7"); err == nil || strings.Contains(err.Error(), fjToken) {
		t.Errorf("redirected read: %v", err)
	}
}

func TestNewForgejoRefusesBadConfiguration(t *testing.T) {
	for name, cfg := range map[string]ForgejoConfig{
		"http":          {BaseURL: "http://forge.corp", Token: []byte(fjToken)},
		"sub-path":      {BaseURL: "https://forge.corp/git", Token: []byte(fjToken)},
		"no token":      {BaseURL: "https://forge.corp"},
		"token space":   {BaseURL: "https://forge.corp", Token: []byte("a b")},
		"bad CA":        {BaseURL: "https://forge.corp", Token: []byte(fjToken), CAPEM: []byte("not pem")},
		"token too big": {BaseURL: "https://forge.corp", Token: []byte(strings.Repeat("a", 256))},
	} {
		if c, err := NewForgejo(cfg); err == nil || c != nil {
			t.Errorf("%s: NewForgejo accepted", name)
		} else if strings.Contains(err.Error(), fjToken) {
			t.Errorf("%s: the error carries the token: %v", name, err)
		}
	}
}

// Only the configured CA is trusted: a server whose certificate it did not
// sign is refused before the token is sent.
func TestForgejoTrustsOnlyTheConfiguredCA(t *testing.T) {
	f := newFJFake(t)
	c, err := NewForgejo(ForgejoConfig{BaseURL: f.srv.URL, Token: []byte(fjToken), CAPEM: anotherCA(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetMRState(context.Background(), fjRepo, "7"); err == nil {
		t.Error("a server outside the configured CA was trusted")
	}
	if f.called() != "" {
		t.Errorf("the token reached an untrusted server: %s", f.called())
	}
}
