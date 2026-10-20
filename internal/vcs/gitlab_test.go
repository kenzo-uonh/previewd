package vcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// The GitLab driver is a Provider (V1.1 spec 3.1).
var _ Provider = (*GitLab)(nil)

const (
	glToken     = "glpat-TESTONLYtokenvalue0123"
	glSecret    = "hook-shared-secret"
	glProject   = "15"
	glPath      = "acme/sub/app"
	glAuthorID  = 4242
	glFork      = "88"
	glHeadSHA   = testHead
	glOldrev    = "fedcba9876543210fedcba9876543210fedcba98"
	glUpdatedAt = "2026-10-20 10:30:05 UTC"
)

// glMRBody is a Merge Request Hook body; edit changes the decoded document
// before it is encoded.
func glMRBody(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	doc := map[string]any{
		"object_kind": "merge_request",
		"event_type":  "merge_request",
		"user":        map[string]any{"id": 99, "username": "pusher.dev"},
		"project": map[string]any{
			"id": 15, "path_with_namespace": glPath, "git_http_url": "https://gitlab.corp/acme/sub/app.git",
		},
		"object_attributes": map[string]any{
			"iid": 7, "action": "update", "oldrev": glOldrev, "state": "opened",
			"source_branch": "feature/login", "target_branch": "main",
			"source_project_id": 15, "target_project_id": 15, "author_id": glAuthorID,
			"updated_at":  glUpdatedAt,
			"last_commit": map[string]any{"id": glHeadSHA},
			"source":      map[string]any{"path_with_namespace": glPath, "git_http_url": "https://gitlab.corp/acme/sub/app.git"},
		},
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

func attrs(doc map[string]any) map[string]any { return doc["object_attributes"].(map[string]any) }

func TestGitLabName(t *testing.T) {
	if got := (&GitLab{}).Name(); got != "gitlab" {
		t.Errorf("Name() = %q, want gitlab", got)
	}
}

func glHook(token string, body string, header ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhooks/gitlab", strings.NewReader(body))
	if token != "" {
		r.Header.Set("X-Gitlab-Token", token)
	}
	for _, extra := range header {
		r.Header.Add("X-Gitlab-Token", extra)
	}
	return r
}

func TestGitLabVerifyWebhookComparesTheTokenInConstantTime(t *testing.T) {
	g := &GitLab{}
	body := string(glMRBody(t, nil))

	r := glHook(glSecret, body)
	got, err := g.VerifyWebhook(r, []byte(glSecret))
	if err != nil || string(got) != body {
		t.Fatalf("VerifyWebhook = %q, %v; want the body", got, err)
	}
	if again, _ := io.ReadAll(r.Body); string(again) != body {
		t.Error("the verified body was not restored for the handler")
	}

	for name, tc := range map[string]struct {
		req    *http.Request
		secret string
	}{
		"no token":           {glHook("", body), glSecret},
		"wrong token":        {glHook("not-the-secret", body), glSecret},
		"prefix of secret":   {glHook(glSecret[:len(glSecret)-1], body), glSecret},
		"secret plus a byte": {glHook(glSecret+"x", body), glSecret},
		"case folded":        {glHook(strings.ToUpper(glSecret), body), glSecret},
		"two tokens":         {glHook(glSecret, body, "other"), glSecret},
		"empty secret":       {glHook("", body), ""},
		"empty both":         {glHook(" ", body), ""},
		"github style header": {func() *http.Request {
			r := glHook("", body)
			r.Header.Set(validate.SignatureHeader, signBody([]byte(glSecret), body))
			return r
		}(), glSecret},
	} {
		if b, err := g.VerifyWebhook(tc.req, []byte(tc.secret)); !errors.Is(err, validate.ErrSignature) || b != nil {
			t.Errorf("%s: VerifyWebhook = %q, %v; want ErrSignature and no body", name, b, err)
		}
	}

	big := strings.Repeat("x", validate.MaxPayloadBytes+1)
	if b, err := g.VerifyWebhook(glHook(glSecret, big), []byte(glSecret)); err == nil || b != nil {
		t.Errorf("an oversized body was accepted: %v", err)
	}
}

// The comparison is subtle.ConstantTimeCompare over digests, so neither the
// content nor the length of the secret shows in the time taken. The error
// never echoes the token it was given.
func TestGitLabVerifyWebhookErrorNeverEchoesTheToken(t *testing.T) {
	_, err := (&GitLab{}).VerifyWebhook(glHook("sup3r-s3cret-guess", "{}"), []byte(glSecret))
	if err == nil || strings.Contains(err.Error(), "sup3r") || strings.Contains(err.Error(), glSecret) {
		t.Errorf("error = %v", err)
	}
}

func TestGitLabParseEvent(t *testing.T) {
	g := &GitLab{}
	parse := func(edit func(map[string]any)) (*Event, error) { return g.ParseEvent(glMRBody(t, edit)) }

	base := Event{
		Action: ActionSynchronize, ProjectID: glProject, Project: glPath, IID: 7,
		HeadRef: "feature/login", HeadSHA: glHeadSHA, HeadProject: glPath,
		CloneURL: "https://gitlab.corp/acme/sub/app.git",
		Author:   Account{ID: glAuthorID}, Sender: Account{Login: "pusher.dev", ID: 99},
		UpdatedAt: time.Date(2026, 10, 20, 10, 30, 5, 0, time.UTC),
	}
	ev, err := parse(nil)
	if err != nil || *ev != base {
		t.Fatalf("push: %+v, %v\nwant %+v", ev, err, base)
	}

	for _, tc := range []struct {
		gitlab, want string
		noOldrev     bool
	}{
		{gitlab: "open", want: ActionOpened},
		{gitlab: "reopen", want: ActionReopened},
		{gitlab: "update", want: ActionSynchronize},
		{gitlab: "close", want: ActionClosed},
		{gitlab: "merge", want: ActionClosed},
		{gitlab: "approved", want: ActionApproved},
		{gitlab: "approval", want: ActionApproved},
		{gitlab: "unapproved", want: ActionUnapproved},
		{gitlab: "unapproval", want: ActionUnapproved},
	} {
		ev, err := parse(func(d map[string]any) { attrs(d)["action"] = tc.gitlab })
		if err != nil || ev.Action != tc.want {
			t.Errorf("action %q: %+v, %v; want %q", tc.gitlab, ev, err, tc.want)
		}
	}

	// An update without a new head (a title, a description, a label) is not a
	// push: nothing to rebuild.
	for name, edit := range map[string]func(map[string]any){
		"update without oldrev": func(d map[string]any) { delete(attrs(d), "oldrev") },
		"update empty oldrev":   func(d map[string]any) { attrs(d)["oldrev"] = "" },
		"unknown action":        func(d map[string]any) { attrs(d)["action"] = "tada" },
		"note hook":             func(d map[string]any) { d["object_kind"] = "note" },
		"push hook":             func(d map[string]any) { d["object_kind"] = "push" },
	} {
		if ev, err := parse(edit); !errors.Is(err, validate.ErrIgnoredAction) || ev != nil {
			t.Errorf("%s: %+v, %v; want ErrIgnoredAction and no event", name, ev, err)
		}
	}

	// A fork: the head lives in another project.
	ev, err = parse(func(d map[string]any) {
		attrs(d)["source_project_id"] = 88
		attrs(d)["source"] = map[string]any{"path_with_namespace": "fork/app", "git_http_url": "https://gitlab.corp/fork/app.git"}
	})
	if err != nil || ev.HeadProject != "fork/app" || ev.ProjectID != glProject || ev.Project != glPath {
		t.Errorf("fork: %+v, %v", ev, err)
	}
	// A deleted fork: no source project at all.
	ev, err = parse(func(d map[string]any) {
		attrs(d)["source_project_id"] = nil
		attrs(d)["source"] = nil
	})
	if err != nil || ev.HeadProject != "" {
		t.Errorf("deleted fork: %+v, %v", ev, err)
	}
}

func TestGitLabParseEventRejectsMissingFields(t *testing.T) {
	for _, path := range [][]string{
		{"object_kind"}, {"user"}, {"user", "id"}, {"user", "username"}, {"project"}, {"project", "id"},
		{"project", "path_with_namespace"}, {"project", "git_http_url"}, {"object_attributes"},
		{"object_attributes", "iid"}, {"object_attributes", "action"}, {"object_attributes", "source_branch"},
		{"object_attributes", "target_project_id"}, {"object_attributes", "author_id"},
		{"object_attributes", "updated_at"}, {"object_attributes", "last_commit"}, {"object_attributes", "last_commit", "id"},
	} {
		ev, err := (&GitLab{}).ParseEvent(glMRBody(t, func(d map[string]any) {
			parent := d
			for _, key := range path[:len(path)-1] {
				parent = parent[key].(map[string]any)
			}
			delete(parent, path[len(path)-1])
		}))
		// A missing object_kind is not a merge request hook at all.
		if path[0] == "object_kind" {
			if !errors.Is(err, validate.ErrPayload) && !errors.Is(err, validate.ErrIgnoredAction) {
				t.Errorf("missing object_kind: %v", err)
			}
			continue
		}
		if !errors.Is(err, validate.ErrPayload) || ev != nil {
			t.Errorf("missing %s: %+v, %v; want ErrPayload", strings.Join(path, "."), ev, err)
		}
	}
	for _, body := range []string{``, `[]`, `{"object_kind":`, `null`} {
		if ev, err := (&GitLab{}).ParseEvent([]byte(body)); !errors.Is(err, validate.ErrPayload) || ev != nil {
			t.Errorf("ParseEvent(%q) = %+v, %v; want ErrPayload", body, ev, err)
		}
	}
}

func TestGitLabParseEventRejectsInvalidFields(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"zero iid":      func(d map[string]any) { attrs(d)["iid"] = 0 },
		"string iid":    func(d map[string]any) { attrs(d)["iid"] = "7" },
		"traversal ref": func(d map[string]any) { attrs(d)["source_branch"] = "../escape" },
		"short sha":     func(d map[string]any) { attrs(d)["last_commit"] = map[string]any{"id": "0123456"} },
		"upper sha":     func(d map[string]any) { attrs(d)["last_commit"] = map[string]any{"id": strings.ToUpper(glHeadSHA)} },
		"bad timestamp": func(d map[string]any) { attrs(d)["updated_at"] = "soon" },
		"zero author":   func(d map[string]any) { attrs(d)["author_id"] = 0 },
		"zero sender":   func(d map[string]any) { d["user"] = map[string]any{"id": 0, "username": "x"} },
		"bad username":  func(d map[string]any) { d["user"] = map[string]any{"id": 9, "username": "a b"} },
		"project path":  func(d map[string]any) { d["project"].(map[string]any)["path_with_namespace"] = "no-namespace" },
		"zero project":  func(d map[string]any) { d["project"].(map[string]any)["id"] = 0 },
		"credentialed clone": func(d map[string]any) {
			d["project"].(map[string]any)["git_http_url"] = "https://u:p@gitlab.corp/a/b.git"
		},
		"relative clone": func(d map[string]any) { d["project"].(map[string]any)["git_http_url"] = "/acme/app.git" },
		"fork path": func(d map[string]any) {
			attrs(d)["source_project_id"] = 88
			attrs(d)["source"] = map[string]any{"path_with_namespace": "../x"}
		},
		"fork without source": func(d map[string]any) { attrs(d)["source_project_id"] = 88; delete(attrs(d), "source") },
		"cross project":       func(d map[string]any) { attrs(d)["target_project_id"] = 16 },
	} {
		if ev, err := (&GitLab{}).ParseEvent(glMRBody(t, edit)); !errors.Is(err, validate.ErrPayload) || ev != nil {
			t.Errorf("%s: %+v, %v; want ErrPayload", name, ev, err)
		}
	}
}

// glFake is a GitLab for one project (15, acme/sub/app) with one merge
// request (7). Its replies are hooks so each test breaks one thing.
type glFake struct {
	t   *testing.T
	srv *httptest.Server

	mu    sync.Mutex
	calls []string // method path

	mr     func() any
	member func() (int, any)
	// others answers a membership read for an account other than the author.
	others func(uid int64) (int, any)
	// project answers GET /projects/:path-or-id for a project path.
	project   func(path string) (int, any)
	approvals func() any
	// archive serves the archive endpoint, when set.
	archive func(w http.ResponseWriter, r *http.Request)
}

func newGLFake(t *testing.T) *glFake {
	t.Helper()
	f := &glFake{t: t}
	f.mr = func() any { return glMR("opened", glProject, glProject) }
	f.member = func() (int, any) {
		return http.StatusOK, map[string]any{"id": glAuthorID, "username": "author", "state": "active", "access_level": 30}
	}
	f.approvals = func() any {
		return map[string]any{"iid": 7, "project_id": 15, "approved_by": []any{
			map[string]any{"user": map[string]any{"id": 7, "username": "lead.dev"}},
			map[string]any{"user": map[string]any{"id": 8, "username": "second"}},
		}}
	}
	f.others = func(uid int64) (int, any) {
		return http.StatusOK, map[string]any{"id": uid, "username": "lead.dev", "state": "active", "access_level": 40}
	}
	f.project = func(path string) (int, any) {
		if path != glPath {
			return http.StatusNotFound, map[string]string{"message": "404 Project Not Found"}
		}
		return http.StatusOK, map[string]any{"id": 15, "path_with_namespace": glPath}
	}
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("PRIVATE-TOKEN") != glToken || strings.Contains(r.URL.String(), glToken) || r.Header.Get("Authorization") != "" {
				t.Errorf("%s %s: not authenticated by PRIVATE-TOKEN alone", r.Method, r.URL)
				http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			f.mu.Lock()
			f.calls = append(f.calls, r.Method+" "+r.URL.Path)
			f.mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api/v4/projects/{path}", guard(func(w http.ResponseWriter, r *http.Request) {
		code, body := f.project(r.PathValue("path"))
		writeJSON(w, code, body)
	}))
	mux.HandleFunc("GET /api/v4/projects/15/merge_requests/7", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, f.mr())
	}))
	mux.HandleFunc("GET /api/v4/projects/15/members/all/{uid}", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("uid") == fmt.Sprint(glAuthorID) {
			code, body := f.member()
			writeJSON(w, code, body)
			return
		}
		var uid int64
		_, _ = fmt.Sscan(r.PathValue("uid"), &uid)
		code, body := f.others(uid)
		writeJSON(w, code, body)
	}))
	mux.HandleFunc("GET /api/v4/projects/15/merge_requests/7/approvals", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, f.approvals())
	}))
	mux.HandleFunc("GET /api/v4/projects/15/repository/archive.tar.gz", guard(func(w http.ResponseWriter, r *http.Request) {
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

func glMR(state, source, target string) map[string]any {
	toInt := func(s string) int { var n int; _, _ = fmt.Sscan(s, &n); return n }
	return map[string]any{
		"iid": 7, "project_id": toInt(target), "state": state, "sha": glHeadSHA,
		"source_project_id": toInt(source), "target_project_id": toInt(target),
		"author": map[string]any{"id": glAuthorID, "username": "author"},
		"labels": []string{"previewd", "needs review"},
	}
}

func (f *glFake) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func (f *glFake) client(t *testing.T, logs io.Writer) *GitLab {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	g, err := NewGitLab(GitLabConfig{BaseURL: f.srv.URL, Token: []byte(glToken), CAPEM: f.caPEM(),
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (f *glFake) called() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

func TestGitLabGetMRState(t *testing.T) {
	f := newGLFake(t)
	st, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7")
	if err != nil {
		t.Fatal(err)
	}
	want := MRState{Open: true, HeadSHA: glHeadSHA, HeadProject: glProject, Author: Account{Login: "author", ID: glAuthorID},
		Trusted: true, Labels: []string{"previewd", "needs review"}}
	if st.Open != want.Open || st.HeadSHA != want.HeadSHA || st.HeadProject != want.HeadProject || st.Author != want.Author ||
		st.Trusted != want.Trusted || strings.Join(st.Labels, "|") != strings.Join(want.Labels, "|") {
		t.Errorf("state = %+v, want %+v", st, want)
	}
	if got, want := f.called(), "GET /api/v4/projects/15/merge_requests/7,GET /api/v4/projects/15/members/all/4242"; got != want {
		t.Errorf("calls %s, want %s", got, want)
	}
}

func TestGitLabTrustNeedsDeveloperAccessInTheBaseProject(t *testing.T) {
	for name, tc := range map[string]struct {
		member  func() (int, any)
		mr      func() any
		trusted bool
		calls   int
	}{
		"developer": {calls: 2, trusted: true},
		"maintainer": {calls: 2, trusted: true, member: func() (int, any) {
			return 200, map[string]any{"id": glAuthorID, "username": "author", "state": "active", "access_level": 40}
		}},
		"owner": {calls: 2, trusted: true, member: func() (int, any) {
			return 200, map[string]any{"id": glAuthorID, "username": "author", "state": "active", "access_level": 50}
		}},
		"reporter": {calls: 2, member: func() (int, any) {
			return 200, map[string]any{"id": glAuthorID, "username": "author", "state": "active", "access_level": 20}
		}},
		"guest": {calls: 2, member: func() (int, any) {
			return 200, map[string]any{"id": glAuthorID, "username": "author", "state": "active", "access_level": 10}
		}},
		"minimal access": {calls: 2, member: func() (int, any) {
			return 200, map[string]any{"id": glAuthorID, "username": "author", "state": "active", "access_level": 5}
		}},
		"blocked member": {calls: 2, member: func() (int, any) {
			return 200, map[string]any{"id": glAuthorID, "username": "author", "state": "blocked", "access_level": 40}
		}},
		"not a member": {calls: 2, member: func() (int, any) { return 404, map[string]string{"message": "404 Not found"} }},
		// A fork is never trusted whatever its author may do upstream, and the
		// membership is not even read.
		"fork":         {calls: 1, mr: func() any { return glMR("opened", glFork, glProject) }},
		"deleted fork": {calls: 1, mr: func() any { d := glMR("opened", glProject, glProject); d["source_project_id"] = nil; return d }},
	} {
		f := newGLFake(t)
		if tc.member != nil {
			f.member = tc.member
		}
		if tc.mr != nil {
			f.mr = tc.mr
		}
		st, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if st.Trusted != tc.trusted {
			t.Errorf("%s: Trusted = %v, want %v", name, st.Trusted, tc.trusted)
		}
		if n := len(strings.Split(f.called(), ",")); n != tc.calls {
			t.Errorf("%s: %d calls (%s), want %d", name, n, f.called(), tc.calls)
		}
	}
}

func TestGitLabGetMRStateStates(t *testing.T) {
	for state, open := range map[string]bool{"opened": true, "closed": false, "merged": false, "locked": false} {
		f := newGLFake(t)
		f.mr = func() any { return glMR(state, glProject, glProject) }
		st, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7")
		if err != nil || st.Open != open {
			t.Errorf("state %q: %+v, %v; want open=%v", state, st, err, open)
		}
	}
	f := newGLFake(t)
	f.mr = func() any { return glMR("zombie", glProject, glProject) }
	if _, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7"); err == nil {
		t.Error("an unknown merge request state was accepted")
	}
}

func TestGitLabGetMRStateRefusesInconsistentReplies(t *testing.T) {
	edit := func(f func(d map[string]any)) func() any {
		return func() any { d := glMR("opened", glProject, glProject); f(d); return d }
	}
	for name, mr := range map[string]func() any{
		"another iid":     edit(func(d map[string]any) { d["iid"] = 8 }),
		"another project": edit(func(d map[string]any) { d["target_project_id"] = 16; d["project_id"] = 16 }),
		"no head":         edit(func(d map[string]any) { delete(d, "sha") }),
		"short head":      edit(func(d map[string]any) { d["sha"] = "0123" }),
		"no author":       edit(func(d map[string]any) { delete(d, "author") }),
		"zero author":     edit(func(d map[string]any) { d["author"] = map[string]any{"id": 0, "username": "x"} }),
		"bad author name": edit(func(d map[string]any) { d["author"] = map[string]any{"id": 5, "username": "a b"} }),
		"no state":        edit(func(d map[string]any) { delete(d, "state") }),
		"no target":       edit(func(d map[string]any) { delete(d, "target_project_id") }),
		"not an object":   func() any { return []int{1} },
	} {
		f := newGLFake(t)
		f.mr = mr
		if st, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7"); err == nil {
			t.Errorf("%s: accepted %+v", name, st)
		}
	}

	// A membership read that fails is an error, not a quiet "untrusted":
	// the caller must be able to tell "no" from "could not tell".
	f := newGLFake(t)
	f.member = func() (int, any) { return 500, map[string]string{"message": "boom"} }
	if _, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7"); err == nil {
		t.Error("a failed membership read was swallowed")
	}
	// So is a membership reply about another account: never "untrusted".
	f.member = func() (int, any) {
		return 200, map[string]any{"id": 1, "username": "someone", "state": "active", "access_level": 50}
	}
	if _, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7"); !errors.Is(err, ErrAccountMismatch) {
		t.Errorf("membership of another account: err = %v, want ErrAccountMismatch", err)
	}
}

func TestGitLabLabelsAreInformationOnly(t *testing.T) {
	f := newGLFake(t)
	f.mr = func() any {
		d := glMR("opened", glProject, glProject)
		d["labels"] = []string{"ok", strings.Repeat("x", 300), "bad\nlabel"}
		return d
	}
	st, err := f.client(t, nil).GetMRState(context.Background(), glProject, "7")
	if err != nil || len(st.Labels) != 1 || st.Labels[0] != "ok" {
		t.Errorf("labels = %v, %v; want only the valid one", st.Labels, err)
	}
}

func TestGitLabGetApprovals(t *testing.T) {
	f := newGLFake(t)
	got, err := f.client(t, nil).GetApprovals(context.Background(), glProject, "7")
	if err != nil {
		t.Fatal(err)
	}
	want := []Approval{{User: Account{Login: "lead.dev", ID: 7}}, {User: Account{Login: "second", ID: 8}}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("approvals = %+v, want %+v (no commit: GitLab does not bind an approval to one)", got, want)
	}
	if got, want := f.called(), "GET /api/v4/projects/15/merge_requests/7/approvals"; got != want {
		t.Errorf("calls %s, want %s", got, want)
	}

	// Matched against PREVIEWD_APPROVERS by account ID: the second account is
	// not listed, so only the lead's approval counts.
	only := Authorized(got, []validate.Approver{{Login: "lead.dev", ID: 7}})
	if len(only) != 1 || only[0].User.ID != 7 {
		t.Errorf("Authorized = %+v", only)
	}
}

func TestGitLabGetApprovalsRefusesBadReplies(t *testing.T) {
	user := func(id int, name string) map[string]any {
		return map[string]any{"user": map[string]any{"id": id, "username": name}}
	}
	for name, reply := range map[string]map[string]any{
		"another iid":     {"iid": 8, "project_id": 15, "approved_by": []any{}},
		"another project": {"iid": 7, "project_id": 16, "approved_by": []any{}},
		"no list":         {"iid": 7, "project_id": 15},
		"zero id":         {"iid": 7, "project_id": 15, "approved_by": []any{user(0, "x")}},
		"bad username":    {"iid": 7, "project_id": 15, "approved_by": []any{user(5, "a b")}},
		"no user":         {"iid": 7, "project_id": 15, "approved_by": []any{map[string]any{}}},
	} {
		f := newGLFake(t)
		f.approvals = func() any { return reply }
		if got, err := f.client(t, nil).GetApprovals(context.Background(), glProject, "7"); err == nil {
			t.Errorf("%s: accepted %+v", name, got)
		}
	}

	// The same account twice is one approval; none is an empty list, not an error.
	f := newGLFake(t)
	f.approvals = func() any {
		return map[string]any{"iid": 7, "project_id": 15, "approved_by": []any{user(7, "lead.dev"), user(7, "lead.dev")}}
	}
	if got, err := f.client(t, nil).GetApprovals(context.Background(), glProject, "7"); err != nil || len(got) != 1 {
		t.Errorf("duplicate: %+v, %v", got, err)
	}
	f.approvals = func() any { return map[string]any{"iid": 7, "project_id": 15, "approved_by": []any{}} }
	if got, err := f.client(t, nil).GetApprovals(context.Background(), glProject, "7"); err != nil || len(got) != 0 {
		t.Errorf("none: %+v, %v", got, err)
	}
}

// Untrusted identifiers are validated before any call: a path, a sign or a
// slash never reaches a URL.
func TestGitLabRefusesBadIdentifiersWithoutACall(t *testing.T) {
	f := newGLFake(t)
	g := f.client(t, nil)
	for _, project := range []string{"", "0", "acme/app", "15/../16", "15?x=1", "-15", "015"} {
		if _, err := g.GetMRState(context.Background(), project, "7"); err == nil {
			t.Errorf("GetMRState project %q accepted", project)
		}
		if _, err := g.GetApprovals(context.Background(), project, "7"); err == nil {
			t.Errorf("GetApprovals project %q accepted", project)
		}
	}
	for _, iid := range []string{"", "0", "7/approvals", "-7", "07", "7 "} {
		if _, err := g.GetMRState(context.Background(), glProject, iid); err == nil {
			t.Errorf("GetMRState iid %q accepted", iid)
		}
		if _, err := g.GetApprovals(context.Background(), glProject, iid); err == nil {
			t.Errorf("GetApprovals iid %q accepted", iid)
		}
	}
	if c := f.called(); c != "" {
		t.Errorf("calls made for invalid identifiers: %s", c)
	}
}

func TestGitLabErrorsNeverCarryTheToken(t *testing.T) {
	f := newGLFake(t)
	f.approvals = func() any { return "not an object" }
	var logs strings.Builder
	_, err := f.client(t, &logs).GetApprovals(context.Background(), glProject, "7")
	if err == nil || strings.Contains(err.Error(), glToken) || strings.Contains(logs.String(), glToken) {
		t.Errorf("error = %v, logs = %q", err, logs.String())
	}
	// An error document quotes the reply, bounded.
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, strings.Repeat("A", 4096), http.StatusForbidden)
	}))
	defer bad.Close()
	g, gerr := NewGitLab(GitLabConfig{BaseURL: bad.URL, Token: []byte(glToken),
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bad.Certificate().Raw})})
	if gerr != nil {
		t.Fatal(gerr)
	}
	_, err = g.GetApprovals(context.Background(), glProject, "7")
	if err == nil || len(err.Error()) > 1024 || !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error = %v", err)
	}
}

func TestGitLabFollowsNoRedirectAndBoundsReplies(t *testing.T) {
	f := newGLFake(t)
	elsewhere := 0
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere++
		writeJSON(w, http.StatusOK, map[string]any{"iid": 7, "project_id": 15, "approved_by": []any{}})
	}))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/15/merge_requests/7/approvals" {
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"pad":"`+strings.Repeat("x", 9<<20)+`"}`)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	_ = f
	g, err := NewGitLab(GitLabConfig{BaseURL: srv.URL, Token: []byte(glToken),
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.GetApprovals(context.Background(), glProject, "7"); err == nil || elsewhere != 0 {
		t.Errorf("redirect followed (%d requests elsewhere), err = %v", elsewhere, err)
	}
	if _, err := g.GetMRState(context.Background(), glProject, "7"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("an oversized reply was accepted: %v", err)
	}
}

func TestNewGitLabRefusesBadConfiguration(t *testing.T) {
	ok := GitLabConfig{BaseURL: "https://gitlab.corp", Token: []byte(glToken)}
	if _, err := NewGitLab(ok); err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	for name, mutate := range map[string]func(c *GitLabConfig){
		"http":           func(c *GitLabConfig) { c.BaseURL = "http://gitlab.corp" },
		"path":           func(c *GitLabConfig) { c.BaseURL = "https://gitlab.corp/gitlab" },
		"no URL":         func(c *GitLabConfig) { c.BaseURL = "" },
		"no token":       func(c *GitLabConfig) { c.Token = nil },
		"token space":    func(c *GitLabConfig) { c.Token = []byte("glpat abc") },
		"token newline":  func(c *GitLabConfig) { c.Token = []byte(glToken + "\n") },
		"token too long": func(c *GitLabConfig) { c.Token = []byte(strings.Repeat("a", 256)) },
		"CA with a key": func(c *GitLabConfig) {
			c.CAPEM = []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
		},
		"CA without cert": func(c *GitLabConfig) { c.CAPEM = []byte("nothing") },
	} {
		c := ok
		mutate(&c)
		if _, err := NewGitLab(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGitLabTransportPolicy(t *testing.T) {
	g, err := NewGitLab(GitLabConfig{BaseURL: "https://gitlab.corp", Token: []byte(glToken)})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := g.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("transport %+v: want no proxy and TLS 1.2 or later", g.http.Transport)
	}
	if g.http.Timeout != callTimeout || g.http.CheckRedirect == nil || g.dl.CheckRedirect == nil {
		t.Error("the API client must be timed out and follow no redirect")
	}
}

// anotherCA is a CA that signed nothing: httptest servers share one
// certificate, so a second server cannot stand for another CA.
func anotherCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGitLabTrustsOnlyTheConfiguredCA(t *testing.T) {
	f := newGLFake(t)
	for name, ca := range map[string][]byte{"system roots": nil, "another CA": anotherCA(t)} {
		g, err := NewGitLab(GitLabConfig{BaseURL: f.srv.URL, Token: []byte(glToken), CAPEM: ca})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.GetApprovals(context.Background(), glProject, "7"); err == nil {
			t.Errorf("%s: a server outside the configured CA was trusted", name)
		}
	}
	if f.called() != "" {
		t.Errorf("the token was sent to an untrusted server: %s", f.called())
	}
}
