package vcs

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGitHubPullRequestHead(t *testing.T) {
	f := newFakeGHES(t)
	h, err := f.client(t, nil).PullRequestHead(context.Background(), testRepo, 7)
	if err != nil {
		t.Fatal(err)
	}
	want := Head{Open: true, Ref: "feature/login", SHA: testHead, HeadProject: testRepo, CloneURL: "https://ghes.example/acme/app.git",
		Author: Account{Login: "opener", ID: testOpenerID}}
	if h != want {
		t.Errorf("head = %+v\nwant   %+v", h, want)
	}
	if f.revoked.Load() != 1 || len(f.minted) != 1 || f.minted[0].Permissions["pull_requests"] != "read" || len(f.minted[0].Permissions) != 1 {
		t.Errorf("tokens: minted %+v, revoked %d; want one pull_requests:read token, revoked", f.minted, f.revoked.Load())
	}

	for name, edit := range map[string]func(map[string]any){
		"no ref":       func(d map[string]any) { d["head"].(map[string]any)["ref"] = "" },
		"bad ref":      func(d map[string]any) { d["head"].(map[string]any)["ref"] = "a..b" },
		"no clone url": func(d map[string]any) { d["base"] = map[string]any{"repo": map[string]string{"full_name": testRepo}} },
		"other repo": func(d map[string]any) {
			d["base"] = map[string]any{"repo": map[string]string{"full_name": "acme/other", "clone_url": "https://x/y.git"}}
		},
	} {
		f.prReply = func() any { d := prDoc(testRepo, "open"); edit(d); return d }
		if h, err := f.client(t, nil).PullRequestHead(context.Background(), testRepo, 7); err == nil {
			t.Errorf("%s: accepted %+v", name, h)
		}
	}
	if _, err := f.client(t, nil).PullRequestHead(context.Background(), testRepo, 0); err == nil {
		t.Error("PR 0 accepted")
	}
}

func TestForgejoPullRequestHead(t *testing.T) {
	f := newFJFake(t)
	c := f.client(t)
	h, err := c.PullRequestHead(context.Background(), fjRepo, 7)
	if err != nil {
		t.Fatal(err)
	}
	want := Head{Open: true, Ref: "feature/login", SHA: testHead, HeadProject: fjRepo, CloneURL: "https://forge.corp/" + fjRepo + ".git",
		Author: Account{Login: "john.doe", ID: fjAuthorID}}
	if h != want {
		t.Errorf("head = %+v\nwant   %+v", h, want)
	}
	// The head is read, not judged: no permission read.
	if strings.Contains(f.called(), "permission") {
		t.Errorf("calls %s", f.called())
	}
	for name, edit := range map[string]func(map[string]any){
		"no ref":       func(d map[string]any) { delete(d["head"].(map[string]any), "ref") },
		"no clone url": func(d map[string]any) { d["base"] = map[string]any{"repo": map[string]any{"full_name": fjRepo}} },
		"bad clone": func(d map[string]any) {
			d["base"].(map[string]any)["repo"].(map[string]any)["clone_url"] = "https://u:p@x/y.git"
		},
	} {
		f.pr = func() any { d := fjPullDoc("open", fjRepo); edit(d); return d }
		if h, err := c.PullRequestHead(context.Background(), fjRepo, 7); err == nil {
			t.Errorf("%s: accepted %+v", name, h)
		}
	}
}

func TestGitLabPullRequestHead(t *testing.T) {
	f := newGLFake(t)
	c := f.client(t, nil)
	h, err := c.PullRequestHead(context.Background(), glPath, 7)
	if err != nil {
		t.Fatal(err)
	}
	want := Head{Open: true, Ref: "feature/login", SHA: glHeadSHA, HeadProject: glPath, CloneURL: "https://gitlab.corp/acme/sub/app.git",
		Author: Account{Login: "author", ID: glAuthorID}}
	if h != want {
		t.Errorf("head = %+v\nwant   %+v", h, want)
	}

	// A fork: its path is read from the fork; one GitLab no longer has is a
	// deleted head.
	f.mr = func() any { return glMR("opened", glFork, glProject) }
	f.project = func(path string) (int, any) {
		switch path {
		case glPath:
			return http.StatusOK, map[string]any{"id": 15, "path_with_namespace": glPath, "http_url_to_repo": "https://gitlab.corp/acme/sub/app.git"}
		case glFork:
			return http.StatusOK, map[string]any{"id": 88, "path_with_namespace": "forker/app"}
		}
		return http.StatusNotFound, map[string]string{"message": "404 Project Not Found"}
	}
	if h, err := c.PullRequestHead(context.Background(), glPath, 7); err != nil || h.HeadProject != "forker/app" {
		t.Errorf("fork: %+v, %v", h, err)
	}
	f.project = func(path string) (int, any) {
		if path == glPath {
			return http.StatusOK, map[string]any{"id": 15, "path_with_namespace": glPath, "http_url_to_repo": "https://gitlab.corp/acme/sub/app.git"}
		}
		return http.StatusNotFound, map[string]string{"message": "404 Project Not Found"}
	}
	if h, err := c.PullRequestHead(context.Background(), glPath, 7); err != nil || h.HeadProject != "" {
		t.Errorf("deleted fork: %+v, %v", h, err)
	}

	for name, tc := range map[string]struct {
		mr      func() any
		project func(string) (int, any)
	}{
		"no source branch": {func() any { d := glMR("opened", glProject, glProject); delete(d, "source_branch"); return d }, nil},
		"renamed project": {nil, func(string) (int, any) {
			return http.StatusOK, map[string]any{"id": 15, "path_with_namespace": "acme/renamed", "http_url_to_repo": "https://gitlab.corp/acme/renamed.git"}
		}},
		"no clone url": {nil, func(string) (int, any) { return http.StatusOK, map[string]any{"id": 15, "path_with_namespace": glPath} }},
	} {
		f := newGLFake(t)
		if tc.mr != nil {
			f.mr = tc.mr
		}
		if tc.project != nil {
			f.project = tc.project
		}
		if h, err := f.client(t, nil).PullRequestHead(context.Background(), glPath, 7); err == nil {
			t.Errorf("%s: accepted %+v", name, h)
		}
	}
	if _, err := c.PullRequestHead(context.Background(), "app", 7); err == nil {
		t.Error("a path without a namespace accepted")
	}
}
