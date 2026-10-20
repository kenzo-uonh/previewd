package vcs

import (
	"archive/tar"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitLabResolveProject(t *testing.T) {
	f := newGLFake(t)
	id, err := f.client(t, nil).ResolveProject(context.Background(), glPath)
	if err != nil || id != glProject {
		t.Fatalf("ResolveProject = %q, %v; want %q", id, err, glProject)
	}
	// The path travels as one encoded segment, never as extra path elements.
	if got, want := f.called(), "GET /api/v4/projects/acme/sub/app"; got != want {
		t.Errorf("calls %s, want %s", got, want)
	}
}

// A path that is not a project path is refused before any call; a reply that
// is not about the path asked for is an error, never a default: the ID is
// what every later call (and the archive of a commit) is addressed by.
func TestGitLabResolveProjectFailsClosed(t *testing.T) {
	for name, path := range map[string]string{
		"empty": "", "no namespace": "app", "traversal": "acme/../app", "trailing slash": "acme/app/",
		"numeric id": "15", "query": "acme/app?x=1", "encoded": "acme%2Fapp",
	} {
		f := newGLFake(t)
		if id, err := f.client(t, nil).ResolveProject(context.Background(), path); err == nil || id != "" {
			t.Errorf("%s: ResolveProject(%q) = %q, %v; want an error", name, path, id, err)
		}
		if got := f.called(); got != "" {
			t.Errorf("%s: a call was made for an invalid path: %s", name, got)
		}
	}

	for name, reply := range map[string]func(string) (int, any){
		"not found": func(string) (int, any) { return http.StatusNotFound, map[string]string{"message": "404"} },
		"another project": func(string) (int, any) {
			return 200, map[string]any{"id": 16, "path_with_namespace": "acme/other"}
		},
		"case differs": func(string) (int, any) {
			return 200, map[string]any{"id": 15, "path_with_namespace": "Acme/sub/app"}
		},
		"no id":      func(string) (int, any) { return 200, map[string]any{"path_with_namespace": glPath} },
		"zero id":    func(string) (int, any) { return 200, map[string]any{"id": 0, "path_with_namespace": glPath} },
		"no path":    func(string) (int, any) { return 200, map[string]any{"id": 15} },
		"server err": func(string) (int, any) { return 500, map[string]string{"message": "boom"} },
	} {
		f := newGLFake(t)
		f.project = reply
		if id, err := f.client(t, nil).ResolveProject(context.Background(), glPath); err == nil || id != "" {
			t.Errorf("%s: ResolveProject = %q, %v; want an error", name, id, err)
		}
	}
}

func TestGitLabFetcherResolvesThenFetchesByID(t *testing.T) {
	f := newGLFake(t)
	f.serveArchive(archive(t, glHeadSHA, entry{name: "Dockerfile", body: "FROM scratch\n", typ: tar.TypeReg}))
	fetcher, err := NewGitLabFetcher(f.client(t, nil), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "src")
	if err := fetcher.Fetch(context.Background(), glPath, "https://gitlab.corp/acme/sub/app.git", glHeadSHA, dest); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "Dockerfile")); err != nil || string(got) != "FROM scratch\n" {
		t.Errorf("Dockerfile = %q, %v", got, err)
	}
	if got, want := f.called(), "GET /api/v4/projects/acme/sub/app,GET /api/v4/projects/15/repository/archive.tar.gz"; got != want {
		t.Errorf("calls %s, want %s", got, want)
	}
}

// The clone URL of a hook is not used: git never runs for a GitLab merge
// request, and an unresolved project fetches nothing.
func TestGitLabFetcherFetchesNothingForAnUnresolvedProject(t *testing.T) {
	f := newGLFake(t)
	f.serveArchive(archive(t, glHeadSHA, entry{name: "a", body: "x", typ: tar.TypeReg}))
	fetcher, err := NewGitLabFetcher(f.client(t, nil), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "src")
	err = fetcher.Fetch(context.Background(), "acme/gone", "file:///etc", glHeadSHA, dest)
	if err == nil {
		t.Fatal("an unresolved project was fetched")
	}
	if strings.Contains(f.called(), "archive") {
		t.Errorf("archive requested for an unresolved project: %s", f.called())
	}
	if _, statErr := os.Lstat(dest); statErr == nil {
		t.Error("a directory was created")
	}
	if errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("err = %v", err)
	}
}

func TestNewGitLabFetcherNeedsADriverAndACap(t *testing.T) {
	if _, err := NewGitLabFetcher(nil, 1); err == nil {
		t.Error("no driver accepted")
	}
	if _, err := NewGitLabFetcher(&GitLab{}, 0); err == nil {
		t.Error("a zero cap accepted")
	}
}
