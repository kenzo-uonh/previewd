package vcs

import (
	"archive/tar"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// serveArchive makes the fake answer the archive endpoint with body and
// records the query.
func (f *glFake) serveArchive(body []byte) *string {
	var query string
	f.archive = func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
	return &query
}

func TestGitLabFetchTarballStreamsTheArchiveUnderTheToken(t *testing.T) {
	f := newGLFake(t)
	query := f.serveArchive(archive(t, glHeadSHA,
		entry{name: "Dockerfile", body: "FROM scratch\n", typ: tar.TypeReg},
		entry{name: "bin/", typ: tar.TypeDir},
		entry{name: "bin/run.sh", body: "#!/bin/sh\n", typ: tar.TypeReg, mode: 0o755},
		entry{name: "latest", link: "bin/run.sh", typ: tar.TypeSymlink},
	))
	dest := filepath.Join(t.TempDir(), "src")
	if err := f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, dest, 1<<20); err != nil {
		t.Fatal(err)
	}
	if *query != "sha="+glHeadSHA {
		t.Errorf("query %q, want sha=%s", *query, glHeadSHA)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "Dockerfile")); err != nil || string(got) != "FROM scratch\n" {
		t.Errorf("Dockerfile = %q, %v", got, err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "bin", "run.sh")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("run.sh = %v, %v; want mode 0755", fi, err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "latest")); err != nil || target != "bin/run.sh" {
		t.Errorf("symlink = %q, %v", target, err)
	}
	if got, want := f.called(), "GET /api/v4/projects/15/repository/archive.tar.gz"; got != want {
		t.Errorf("calls %s, want %s", got, want)
	}
}

func TestGitLabFetchTarballRefusesWhatIsNotTheCommitOrIsUnsafe(t *testing.T) {
	const other = "fedcba9876543210fedcba9876543210fedcba98"
	for name, body := range map[string][]byte{
		"another commit": archive(t, other, entry{name: "a", body: "x", typ: tar.TypeReg}),
		"no commit":      archive(t, "", entry{name: "a", body: "x", typ: tar.TypeReg}),
		"zip slip":       archive(t, glHeadSHA, entry{name: "../../evil", body: "x", typ: tar.TypeReg, raw: true}),
		"absolute":       archive(t, glHeadSHA, entry{name: "/etc/evil", body: "x", typ: tar.TypeReg, raw: true}),
		"symlink out":    archive(t, glHeadSHA, entry{name: "l", link: "../../etc/passwd", typ: tar.TypeSymlink}),
		"hard link":      archive(t, glHeadSHA, entry{name: "h", link: "a", typ: tar.TypeLink}),
		"device":         archive(t, glHeadSHA, entry{name: "d", typ: tar.TypeChar}),
		"not gzip":       []byte("<html>sign in</html>"),
	} {
		f := newGLFake(t)
		f.serveArchive(body)
		root := t.TempDir()
		err := f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(root, "src"), 1<<20)
		if !errors.Is(err, ErrUnsafeArchive) {
			t.Errorf("%s: err = %v, want ErrUnsafeArchive", name, err)
		}
		if _, statErr := os.Lstat(filepath.Join(root, "evil")); statErr == nil {
			t.Errorf("%s: a file was written outside the tree", name)
		}
	}
}

func TestGitLabFetchTarballBoundsTheArchive(t *testing.T) {
	big := archive(t, glHeadSHA, entry{name: "blob", body: strings.Repeat("A", 4096), typ: tar.TypeReg})

	// Above the cap in extracted bytes.
	f := newGLFake(t)
	f.serveArchive(big)
	err := f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(t.TempDir(), "src"), 1024)
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("extracted bytes: err = %v, want ErrUnsafeArchive", err)
	}

	// Above the cap in compressed bytes: refused from Content-Length, before
	// anything is extracted.
	dest := filepath.Join(t.TempDir(), "src")
	f = newGLFake(t)
	f.serveArchive(big)
	err = f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, dest, int64(len(big))-1)
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("compressed bytes: err = %v", err)
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("a directory was created for an archive refused by its size")
	}

	// An unannounced length (chunked) is still bounded while it streams.
	f = newGLFake(t)
	f.archive = func(w http.ResponseWriter, r *http.Request) {
		for range 100 {
			_, _ = w.Write(big)
			w.(http.Flusher).Flush()
		}
	}
	if err := f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(t.TempDir(), "src"), int64(len(big))+10); err == nil {
		t.Error("an endless chunked archive was accepted")
	}
}

func TestGitLabFetchTarballFollowsNoRedirect(t *testing.T) {
	hits := 0
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("PRIVATE-TOKEN") != "" {
			t.Error("the token was forwarded to another host")
		}
	}))
	defer other.Close()
	f := newGLFake(t)
	f.archive = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/archive", http.StatusFound)
	}
	dest := filepath.Join(t.TempDir(), "src")
	err := f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, dest, 1<<20)
	if err == nil || hits != 0 {
		t.Errorf("redirect followed (%d hits), err = %v", hits, err)
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Error("a directory was created for a refused redirect")
	}
}

func TestGitLabFetchTarballRefusesFailuresWithoutTheToken(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError} {
		f := newGLFake(t)
		f.archive = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", code) }
		err := f.client(t, nil).FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(t.TempDir(), "src"), 1<<20)
		if err == nil || !strings.Contains(err.Error(), strconv.Itoa(code)) || strings.Contains(err.Error(), glToken) {
			t.Errorf("HTTP %d: err = %v", code, err)
		}
	}
}

func TestGitLabFetchTarballRefusesBadArguments(t *testing.T) {
	f := newGLFake(t)
	g := f.client(t, nil)
	root := t.TempDir()
	existing := filepath.Join(root, "exists")
	if err := os.Mkdir(existing, 0o750); err != nil {
		t.Fatal(err)
	}
	f.serveArchive(archive(t, glHeadSHA, entry{name: "a", body: "x", typ: tar.TypeReg}))
	for name, call := range map[string]func() error{
		"path as project": func() error {
			return g.FetchTarball(context.Background(), "acme/app", glHeadSHA, filepath.Join(root, "a"), 1<<20)
		},
		"short sha": func() error {
			return g.FetchTarball(context.Background(), glProject, "0123", filepath.Join(root, "b"), 1<<20)
		},
		"branch as sha": func() error {
			return g.FetchTarball(context.Background(), glProject, "main", filepath.Join(root, "c"), 1<<20)
		},
		"query smuggling": func() error {
			return g.FetchTarball(context.Background(), glProject, glHeadSHA+"&path=..", filepath.Join(root, "d"), 1<<20)
		},
		"zero cap": func() error {
			return g.FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(root, "e"), 0)
		},
		"negative cap": func() error {
			return g.FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(root, "f"), -1)
		},
		"destination exists": func() error { return g.FetchTarball(context.Background(), glProject, glHeadSHA, existing, 1<<20) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Only the existing destination got as far as a download.
	if c := f.called(); strings.Count(c, "archive.tar.gz") > 1 {
		t.Errorf("calls for invalid arguments: %s", c)
	}
}

func TestGitLabFetchTarballTrustsOnlyTheConfiguredCA(t *testing.T) {
	f := newGLFake(t)
	f.serveArchive(archive(t, glHeadSHA, entry{name: "a", body: "x", typ: tar.TypeReg}))
	g, err := NewGitLab(GitLabConfig{BaseURL: f.srv.URL, Token: []byte(glToken), CAPEM: anotherCA(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.FetchTarball(context.Background(), glProject, glHeadSHA, filepath.Join(t.TempDir(), "src"), 1<<20); err == nil {
		t.Error("an archive from a server outside the CA was accepted")
	}
	if f.called() != "" {
		t.Errorf("the token was sent to an untrusted server: %s", f.called())
	}
}
