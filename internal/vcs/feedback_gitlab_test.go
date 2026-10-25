package vcs

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const glBotID = 555 // the account the access token acts as

type glStatus struct{ SHA, State, Name, TargetURL, Description string }

type glNote struct {
	ID       int64
	Body     string
	AuthorID int64
	System   bool
}

func (f *glFake) feedbackRoutes(mux *http.ServeMux, guard func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/v4/user", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": glBotID, "username": "project_15_bot"})
	}))
	mux.HandleFunc("POST /api/v4/projects/15/statuses/{sha}", guard(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			State       string `json:"state"`
			Name        string `json:"name"`
			TargetURL   string `json:"target_url"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			f.t.Errorf("status body: %v", err)
		}
		f.mu.Lock()
		f.statuses = append(f.statuses, glStatus{r.PathValue("sha"), in.State, in.Name, in.TargetURL, in.Description})
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": 1})
	}))
	mux.HandleFunc("GET /api/v4/projects/15/merge_requests/7/notes", guard(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size := f.notePage
		if size == 0 {
			size = 100
		}
		if r.URL.Query().Get("per_page") != "100" || page < 1 {
			f.t.Errorf("notes query %q", r.URL.RawQuery)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []map[string]any
		for i := (page - 1) * size; i < min(page*size, len(f.notes)); i++ {
			n := f.notes[i]
			out = append(out, map[string]any{"id": n.ID, "body": n.Body, "system": n.System, "author": map[string]any{"id": n.AuthorID}})
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("POST /api/v4/projects/15/merge_requests/7/notes", guard(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		n := &glNote{ID: int64(1000 + len(f.notes)), Body: in.Body, AuthorID: glBotID}
		f.notes = append(f.notes, n)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": n.ID})
	}))
	mux.HandleFunc("PUT /api/v4/projects/15/merge_requests/7/notes/{id}", guard(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, n := range f.notes {
			if strconv.FormatInt(n.ID, 10) != r.PathValue("id") {
				continue
			}
			if n.AuthorID != glBotID {
				writeJSON(w, http.StatusForbidden, map[string]string{"message": "403 Forbidden"})
				return
			}
			n.Body = in.Body
			writeJSON(w, http.StatusOK, map[string]any{"id": n.ID})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "404 Not found"})
	}))
}

func TestGitLabSetCommitStatus(t *testing.T) {
	f := newGLFake(t)
	g := f.client(t, nil)
	ctx := context.Background()
	if err := g.SetCommitStatus(ctx, glProject, glHeadSHA, StateSuccess, "https://pr-7-0a0a0a0a0a.preview.corp", "Preview ready"); err != nil {
		t.Fatal(err)
	}
	if err := g.SetCommitStatus(ctx, glProject, glHeadSHA, StateFailure, "", "Preview failed at build"); err != nil {
		t.Fatal(err)
	}
	if err := g.SetCommitStatus(ctx, glProject, glHeadSHA, StatePending, "", "Deploying the preview"); err != nil {
		t.Fatal(err)
	}
	want := []glStatus{
		{glHeadSHA, "success", "previewd", "https://pr-7-0a0a0a0a0a.preview.corp", "Preview ready"},
		{glHeadSHA, "failed", "previewd", "", "Preview failed at build"}, // GitLab spells failure "failed"
		{glHeadSHA, "pending", "previewd", "", "Deploying the preview"},
	}
	if len(f.statuses) != 3 || f.statuses[0] != want[0] || f.statuses[1] != want[1] || f.statuses[2] != want[2] {
		t.Errorf("statuses = %+v\nwant %+v", f.statuses, want)
	}
}

// Fails closed on the arguments, before any call.
func TestGitLabFeedbackRefusesBadArguments(t *testing.T) {
	f := newGLFake(t)
	g := f.client(t, nil)
	ctx := context.Background()
	for name, err := range map[string]error{
		"state":      g.SetCommitStatus(ctx, glProject, glHeadSHA, "canceled", "", "d"),
		"sha":        g.SetCommitStatus(ctx, glProject, "abc", StateSuccess, "", "d"),
		"url":        g.SetCommitStatus(ctx, glProject, glHeadSHA, StateSuccess, "https://u:p@x.corp", "d"),
		"path":       g.SetCommitStatus(ctx, "acme/app", glHeadSHA, StateSuccess, "", "d"),
		"zero id":    g.SetCommitStatus(ctx, "0", glHeadSHA, StateSuccess, "", "d"),
		"no marker":  g.PostComment(ctx, glProject, "7", "hello"),
		"iid":        g.PostComment(ctx, glProject, "07", CommentMarker+"\nx"),
		"path again": g.PostComment(ctx, "acme/app", "7", CommentMarker+"\nx"),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if got := f.called(); got != "" {
		t.Errorf("calls for refused arguments: %s", got)
	}
}

func TestGitLabPostCommentCreatesThenUpdatesInPlace(t *testing.T) {
	f := newGLFake(t)
	g := f.client(t, nil)
	ctx := context.Background()
	body := func(n int) string { return CommentMarker + "\nrun " + strconv.Itoa(n) }
	for i := 1; i <= 4; i++ {
		if err := g.PostComment(ctx, glProject, "7", body(i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.notes) != 1 || f.notes[0].Body != body(4) {
		t.Errorf("%d notes, %+v; want one note holding run 4", len(f.notes), f.notes)
	}
}

func TestGitLabPostCommentSkipsAnUnchangedBody(t *testing.T) {
	f := newGLFake(t)
	g := f.client(t, nil)
	for range 3 {
		if err := g.PostComment(context.Background(), glProject, "7", CommentMarker+"\nsame"); err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	for _, c := range strings.Split(f.called(), ",") {
		if strings.HasPrefix(c, "POST") || strings.HasPrefix(c, "PUT") {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("%d writes for 3 identical posts: %s", writes, f.called())
	}
}

// Never another account's note, and never a system note.
func TestGitLabPostCommentIgnoresNotes(t *testing.T) {
	f := newGLFake(t)
	f.notes = []*glNote{
		{ID: 1, Body: CommentMarker + "\nforged", AuthorID: 99},
		{ID: 2, Body: CommentMarker + "\nsystem", AuthorID: glBotID, System: true},
		{ID: 3, Body: "unrelated", AuthorID: glBotID},
	}
	if err := f.client(t, nil).PostComment(context.Background(), glProject, "7", CommentMarker+"\nreal"); err != nil {
		t.Fatal(err)
	}
	if len(f.notes) != 4 || f.notes[3].Body != CommentMarker+"\nreal" || f.notes[0].Body != CommentMarker+"\nforged" || f.notes[1].Body != CommentMarker+"\nsystem" {
		t.Errorf("notes = %+v", f.notes)
	}
}

func TestGitLabPostCommentFindsItsNoteOnALaterPage(t *testing.T) {
	f := newGLFake(t)
	f.notePage = 100
	for i := range 130 {
		f.notes = append(f.notes, &glNote{ID: int64(i + 1), Body: "chatter", AuthorID: 99})
	}
	f.notes = append(f.notes, &glNote{ID: 500, Body: CommentMarker + "\nold", AuthorID: glBotID})
	if err := f.client(t, nil).PostComment(context.Background(), glProject, "7", CommentMarker+"\nnew"); err != nil {
		t.Fatal(err)
	}
	if len(f.notes) != 131 || f.notes[130].Body != CommentMarker+"\nnew" {
		t.Errorf("%d notes, last %q; want the sticky note updated in place", len(f.notes), f.notes[len(f.notes)-1].Body)
	}
}

func TestGitLabPostCommentBoundsTheSearch(t *testing.T) {
	f := newGLFake(t)
	f.notePage = 100
	for i := range (maxCommentPages + 2) * 100 {
		f.notes = append(f.notes, &glNote{ID: int64(i + 1), Body: "x", AuthorID: 99})
	}
	if err := f.client(t, nil).PostComment(context.Background(), glProject, "7", CommentMarker+"\nnew"); err == nil {
		t.Fatal("a thread of more than the bound was searched without end")
	}
	pages := strings.Count(f.called(), "/notes")
	if pages > maxCommentPages {
		t.Errorf("%d notes calls, want at most %d", pages, maxCommentPages)
	}
	if len(f.notes) != (maxCommentPages+2)*100 {
		t.Error("a note was written after an unbounded search")
	}
}

// The token's account is read from GitLab, never assumed: a reply that names
// no account makes no note writable.
func TestGitLabPostCommentNeedsToKnowItsOwnAccount(t *testing.T) {
	f := newGLFake(t)
	f.srv.Config.Handler = http.NotFoundHandler() // /user answers 404
	if err := f.client(t, nil).PostComment(context.Background(), glProject, "7", CommentMarker+"\nx"); err == nil {
		t.Error("a comment was posted without knowing which notes are its own")
	}
}

// The token carries no write scope: the forge refuses, the caller learns.
func TestGitLabFeedbackReportsARefusedWrite(t *testing.T) {
	f := newGLFake(t)
	old := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "403 Forbidden"})
			return
		}
		old.ServeHTTP(w, r)
	})
	if err := f.client(t, nil).SetCommitStatus(context.Background(), glProject, glHeadSHA, StateSuccess, "", "d"); err == nil {
		t.Error("a refused status write was reported as done")
	}
}
