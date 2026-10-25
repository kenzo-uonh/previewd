package vcs

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type ghStatus struct {
	SHA, State, TargetURL, Description, Context string
}

type ghComment struct {
	ID    int64
	Body  string
	AppID int64 // performed_via_github_app; 0: a person
	Login string
}

// grantWrite makes the fake grant exactly what the request names, as GitHub does.
func (f *fakeGHES) grantWrite() {
	f.tokenReply = func() any {
		f.mu.Lock()
		perms := map[string]string{"metadata": "read"}
		for p, level := range f.minted[len(f.minted)-1].Permissions {
			perms[p] = level
		}
		f.mu.Unlock()
		return map[string]any{
			"token": testToken, "expires_at": futureExpiry(), "permissions": perms,
			"repositories": []map[string]string{{"full_name": testRepo}},
		}
	}
}

func (f *fakeGHES) feedbackRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v3/repos/acme/app/statuses/{sha}", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		var in struct {
			State       string `json:"state"`
			TargetURL   string `json:"target_url"`
			Description string `json:"description"`
			Context     string `json:"context"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			f.t.Errorf("status body: %v", err)
		}
		f.mu.Lock()
		f.statuses = append(f.statuses, ghStatus{r.PathValue("sha"), in.State, in.TargetURL, in.Description, in.Context})
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": 1})
	})
	mux.HandleFunc("GET /api/v3/repos/acme/app/issues/7/comments", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size := f.commentPage
		if size == 0 {
			size = 100
		}
		if r.URL.Query().Get("per_page") != "100" || page < 1 {
			f.t.Errorf("comments query %q", r.URL.RawQuery)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []map[string]any
		for i := (page - 1) * size; i < min(page*size, len(f.comments)); i++ {
			c := f.comments[i]
			doc := map[string]any{"id": c.ID, "body": c.Body, "user": map[string]any{"login": c.Login, "id": 1}}
			if c.AppID != 0 {
				doc["performed_via_github_app"] = map[string]any{"id": c.AppID}
			}
			out = append(out, doc)
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /api/v3/repos/acme/app/issues/7/comments", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		c := &ghComment{ID: int64(1000 + len(f.comments)), Body: in.Body, AppID: testAppID, Login: "previewd[bot]"}
		f.comments = append(f.comments, c)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": c.ID})
	})
	mux.HandleFunc("PATCH /api/v3/repos/acme/app/issues/comments/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.comments {
			if strconv.FormatInt(c.ID, 10) != r.PathValue("id") {
				continue
			}
			if c.AppID != testAppID { // GitHub: an App cannot edit what it did not write
				writeJSON(w, http.StatusForbidden, map[string]string{"message": "Resource not accessible by integration"})
				return
			}
			c.Body = in.Body
			writeJSON(w, http.StatusOK, map[string]any{"id": c.ID})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
	})
}

func futureExpiry() string { return timeNowPlusHour() }

func (f *fakeGHES) lastMint(t *testing.T) tokenRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.minted) == 0 {
		t.Fatal("no token minted")
	}
	return f.minted[len(f.minted)-1]
}

func TestGitHubSetCommitStatus(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	err := f.client(t, nil).SetCommitStatus(context.Background(), testRepo, testHead, StateSuccess, "https://pr-7-0a0a0a0a0a.preview.corp", "Preview ready")
	if err != nil {
		t.Fatal(err)
	}
	want := ghStatus{testHead, "success", "https://pr-7-0a0a0a0a0a.preview.corp", "Preview ready", "previewd"}
	if len(f.statuses) != 1 || f.statuses[0] != want {
		t.Errorf("statuses = %+v, want %+v", f.statuses, want)
	}
	// Write access to the one permission, for the one repository, revoked after.
	if req := f.lastMint(t); len(req.Permissions) != 1 || req.Permissions["statuses"] != "write" || len(req.Repositories) != 1 || req.Repositories[0] != "app" {
		t.Errorf("token request = %+v; want statuses:write on app alone", req)
	}
	if f.revoked.Load() != 1 {
		t.Errorf("token revoked %d times", f.revoked.Load())
	}
}

func TestGitHubSetCommitStatusMapsFailure(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	if err := f.client(t, nil).SetCommitStatus(context.Background(), testRepo, testHead, StateFailure, "", "Preview failed at build"); err != nil {
		t.Fatal(err)
	}
	if len(f.statuses) != 1 || f.statuses[0].State != "failure" || f.statuses[0].TargetURL != "" {
		t.Errorf("statuses = %+v", f.statuses)
	}
}

// Fails closed on the arguments, before a token is minted.
func TestGitHubFeedbackRefusesBadArguments(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	c := f.client(t, nil)
	ctx := context.Background()
	for name, err := range map[string]error{
		"state":     c.SetCommitStatus(ctx, testRepo, testHead, "error", "", "d"),
		"sha":       c.SetCommitStatus(ctx, testRepo, "abc", StateSuccess, "", "d"),
		"url":       c.SetCommitStatus(ctx, testRepo, testHead, StateSuccess, "javascript:x", "d"),
		"repo":      c.SetCommitStatus(ctx, "../x", testHead, StateSuccess, "", "d"),
		"no marker": c.PostComment(ctx, testRepo, "7", "hello"),
		"iid":       c.PostComment(ctx, testRepo, "07", CommentMarker+"\nx"),
		"zero iid":  c.PostComment(ctx, testRepo, "0", CommentMarker+"\nx"),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if len(f.minted) != 0 {
		t.Errorf("%d tokens minted for refused calls", len(f.minted))
	}
}

func TestGitHubPostCommentCreatesThenUpdatesInPlace(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	c := f.client(t, nil)
	ctx := context.Background()
	body := func(n int) string { return CommentMarker + "\nrun " + strconv.Itoa(n) }

	if err := c.PostComment(ctx, testRepo, "7", body(1)); err != nil {
		t.Fatal(err)
	}
	if len(f.comments) != 1 || f.comments[0].Body != body(1) {
		t.Fatalf("comments after the first post: %+v", f.comments)
	}
	if req := f.lastMint(t); len(req.Permissions) != 1 || req.Permissions["pull_requests"] != "write" {
		t.Errorf("token request = %+v; want pull_requests:write alone", req)
	}
	for i := 2; i <= 4; i++ {
		if err := c.PostComment(ctx, testRepo, "7", body(i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.comments) != 1 || f.comments[0].Body != body(4) {
		t.Errorf("sticky comment: %d comments, last %q; want one comment holding run 4", len(f.comments), f.comments[len(f.comments)-1].Body)
	}
}

// Idempotent: the same body twice is one write.
func TestGitHubPostCommentSkipsAnUnchangedBody(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	c := f.client(t, nil)
	b := CommentMarker + "\nsame"
	for range 3 {
		if err := c.PostComment(context.Background(), testRepo, "7", b); err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	for _, call := range f.calls {
		if strings.HasPrefix(call, "POST") || strings.HasPrefix(call, "PATCH") {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("%d writes for 3 identical posts: %v", writes, f.calls)
	}
}

// Never another account's comment: a person who copies the marker does not
// become the sticky comment, and is not edited.
func TestGitHubPostCommentIgnoresComments(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	f.comments = []*ghComment{
		{ID: 1, Body: CommentMarker + "\nforged", Login: "mallory"},                   // a person
		{ID: 2, Body: CommentMarker + "\nother app", AppID: 999, Login: "other[bot]"}, // another App
		{ID: 3, Body: "unrelated", AppID: testAppID, Login: "previewd[bot]"},          // ours, no marker
	}
	if err := f.client(t, nil).PostComment(context.Background(), testRepo, "7", CommentMarker+"\nreal"); err != nil {
		t.Fatal(err)
	}
	if len(f.comments) != 4 || f.comments[3].Body != CommentMarker+"\nreal" || f.comments[0].Body != CommentMarker+"\nforged" || f.comments[1].Body != CommentMarker+"\nother app" {
		t.Errorf("comments = %+v", f.comments)
	}
}

func TestGitHubPostCommentFindsItsCommentOnALaterPage(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	f.commentPage = 100
	for i := range 130 {
		f.comments = append(f.comments, &ghComment{ID: int64(i + 1), Body: "chatter " + strconv.Itoa(i), Login: "dev"})
	}
	f.comments = append(f.comments, &ghComment{ID: 500, Body: CommentMarker + "\nold", AppID: testAppID, Login: "previewd[bot]"})
	if err := f.client(t, nil).PostComment(context.Background(), testRepo, "7", CommentMarker+"\nnew"); err != nil {
		t.Fatal(err)
	}
	if len(f.comments) != 131 || f.comments[130].Body != CommentMarker+"\nnew" {
		t.Errorf("%d comments, last %q; want the sticky comment updated in place", len(f.comments), f.comments[len(f.comments)-1].Body)
	}
}

// A listing that never ends is not followed forever: the comment is created
// rather than searched for without bound.
func TestGitHubPostCommentBoundsTheSearch(t *testing.T) {
	f := newFakeGHES(t)
	f.grantWrite()
	f.commentPage = 100
	for i := range (maxCommentPages + 2) * 100 {
		f.comments = append(f.comments, &ghComment{ID: int64(i + 1), Body: "x", Login: "dev"})
	}
	err := f.client(t, nil).PostComment(context.Background(), testRepo, "7", CommentMarker+"\nnew")
	if err == nil {
		t.Fatalf("a thread of %d comments was searched without bound", len(f.comments))
	}
	pages := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "GET") && strings.HasSuffix(c, "/comments") {
			pages++
		}
	}
	if pages > maxCommentPages {
		t.Errorf("%d pages read, want at most %d", pages, maxCommentPages)
	}
}

// A forge that refuses the write (the App lacks the permission) is an
// error for the caller to log, never a panic or a silent success.
func TestGitHubFeedbackReportsARefusedWrite(t *testing.T) {
	f := newFakeGHES(t) // the default token reply grants read only
	if err := f.client(t, nil).SetCommitStatus(context.Background(), testRepo, testHead, StateSuccess, "", "d"); err == nil {
		t.Error("a read-only grant was accepted for a write")
	}
}

func timeNowPlusHour() string { return time.Now().Add(time.Hour).UTC().Format(time.RFC3339) }
