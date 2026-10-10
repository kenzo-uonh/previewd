package vcs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// archivePrefix is the top-level directory GitHub names an archive's tree.
const archivePrefix = "acme-app-0123456/"

// entry is one tar entry of a test archive, named under archivePrefix
// unless raw.
type entry struct {
	name, body, link string
	typ              byte
	mode             int64
	raw              bool
}

// archive builds a gzip tar as GitHub writes one: a pax global header
// naming commit (none when commit is ""), the top-level directory, then
// entries.
func archive(t *testing.T, commit string, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if commit != "" {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header",
			PAXRecords: map[string]string{"comment": commit}, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
	}
	all := append([]entry{{name: archivePrefix, typ: tar.TypeDir, mode: 0o775, raw: true}}, entries...)
	for _, e := range all {
		name := e.name
		if !e.raw {
			name = archivePrefix + name
		}
		hdr := &tar.Header{Name: name, Typeflag: e.typ, Mode: cmpMode(e.mode), Linkname: e.link, Size: int64(len(e.body)), Format: tar.FormatPAX}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if hdr.Size > 0 {
			if _, err := io.WriteString(tw, e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cmpMode(m int64) int64 {
	if m == 0 {
		return 0o664
	}
	return m
}

func file(name, body string) entry { return entry{name: name, body: body, typ: tar.TypeReg} }
func dir(name string) entry        { return entry{name: name + "/", typ: tar.TypeDir, mode: 0o775} }
func symlink(name, target string) entry {
	return entry{name: name, link: target, typ: tar.TypeSymlink, mode: 0o777}
}

// A GitHub archive of the commit is extracted under destDir without its
// top-level directory: directories, files (0644, or 0755 when executable)
// and symlinks inside the tree.
func TestExtractTarball(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "src")
	data := archive(t, testHead,
		file("Dockerfile", "FROM scratch\n"),
		dir("src"),
		file("src/main.go", "package main\n"),
		entry{name: "run.sh", body: "#!/bin/sh\n", typ: tar.TypeReg, mode: 0o4775},
		symlink("main.go", "src/main.go"),
		symlink("src/up", "../Dockerfile"),
	)
	if err := extractTarball(bytes.NewReader(data), testHead, dest, 1<<20, 100); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"Dockerfile": "FROM scratch\n", "src/main.go": "package main\n", "main.go": "package main\n", "src/up": "FROM scratch\n"} {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	for name, want := range map[string]os.FileMode{"Dockerfile": 0o644, "run.sh": 0o755} {
		fi, err := os.Lstat(filepath.Join(dest, name))
		if err != nil || fi.Mode().Perm()&^0o022 != want&^0o022 || fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			t.Fatalf("%s mode %v (%v), want %v without setuid", name, fi.Mode(), err, want)
		}
	}
	if target, err := os.Readlink(filepath.Join(dest, "main.go")); err != nil || target != "src/main.go" {
		t.Fatalf("main.go -> %q, %v", target, err)
	}
}

// Every entry that could leave the tree or exceed the bounds refuses the
// whole archive (ErrUnsafeArchive), and nothing is written outside it.
func TestExtractTarballRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		commit     string
		entries    []entry
		maxBytes   int64
		maxEntries int
	}{
		"absolute path":           {entries: []entry{{name: "/etc/passwd", body: "x", typ: tar.TypeReg, raw: true}}},
		"dot-dot":                 {entries: []entry{file("../outside", "x")}},
		"dot-dot inside":          {entries: []entry{dir("a"), file("a/../../outside", "x")}},
		"non-clean":               {entries: []entry{file("a//b", "x")}},
		"dot element":             {entries: []entry{file("./x", "x")}},
		"backslash":               {entries: []entry{file(`a\..\..\outside`, "x")}},
		"other top-level dir":     {entries: []entry{{name: "other/x", body: "x", typ: tar.TypeReg, raw: true}}},
		"absolute symlink":        {entries: []entry{symlink("passwd", "/etc/passwd")}},
		"symlink out":             {entries: []entry{symlink("up", "../../outside")}},
		"nested symlink out":      {entries: []entry{dir("a"), symlink("a/up", "../../outside")}},
		"hard link":               {entries: []entry{file("x", "x"), {name: "y", link: archivePrefix + "x", typ: tar.TypeLink}}},
		"char device":             {entries: []entry{{name: "null", typ: tar.TypeChar}}},
		"block device":            {entries: []entry{{name: "sda", typ: tar.TypeBlock}}},
		"fifo":                    {entries: []entry{{name: "pipe", typ: tar.TypeFifo}}},
		"duplicate":               {entries: []entry{file("x", "a"), file("x", "b")}},
		"file over a directory":   {entries: []entry{dir("x"), file("x", "a")}},
		"no global header":        {commit: "-"},
		"another commit":          {commit: strings.Repeat("f", 40)},
		"content above the cap":   {entries: []entry{file("a", "12345"), file("b", "123456")}, maxBytes: 10},
		"more entries than cap":   {entries: []entry{file("a", ""), file("b", ""), file("c", "")}, maxEntries: 3},
		"top-level entry is file": {entries: []entry{{name: "README", body: "x", typ: tar.TypeReg, raw: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dest := filepath.Join(base, "build", "src")
			if err := os.Mkdir(filepath.Dir(dest), 0o750); err != nil {
				t.Fatal(err)
			}
			commit := testHead
			switch tc.commit {
			case "-":
				commit = ""
			case "":
			default:
				commit = tc.commit
			}
			maxBytes, maxEntries := cmpInt(tc.maxBytes, 1<<20), int(cmpInt(int64(tc.maxEntries), 100))
			err := extractTarball(bytes.NewReader(archive(t, commit, tc.entries...)), testHead, dest, maxBytes, maxEntries)
			if !errors.Is(err, ErrUnsafeArchive) {
				t.Fatalf("extract = %v, want ErrUnsafeArchive", err)
			}
			for _, p := range []string{filepath.Join(base, "outside"), filepath.Join(base, "build", "outside"), "/etc/passwd.previewd-test"} {
				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s written outside the tree (%v)", p, err)
				}
			}
		})
	}
}

func cmpInt(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}

// Not an archive, a cut archive, and an existing destination fail.
func TestExtractTarballRefusesBrokenInput(t *testing.T) {
	good := archive(t, testHead, file("Dockerfile", strings.Repeat("x", 4096)))
	for name, data := range map[string][]byte{"not gzip": []byte("PK\x03\x04 a zip"), "cut": good[:len(good)/2]} {
		if err := extractTarball(bytes.NewReader(data), testHead, filepath.Join(t.TempDir(), "src"), 1<<20, 100); err == nil {
			t.Errorf("%s: extracted", name)
		}
	}
	if err := extractTarball(bytes.NewReader(good), testHead, t.TempDir(), 1<<20, 100); err == nil {
		t.Error("extracted into an existing directory")
	}
}

// fakeArchive adds the tarball API and the archive host to f. The API
// answers with redirect (the archive URL on f by default); the archive
// handler serves data and records what each download carried.
type fakeArchive struct {
	mu       sync.Mutex
	data     []byte
	redirect func(base string) string
	apiCode  int
	dlCode   int
	chunked  bool
	auths    []string // Authorization header of each download
	queries  []string // each tarball API path
}

const archiveCode = "s3cr3t-c0de-in-url"

// dropConnection makes the archive host close the connection unanswered.
const dropConnection = -1

func (f *fakeGHES) withArchive(t *testing.T, a *fakeArchive) {
	t.Helper()
	f.tokenReply = func() any {
		return map[string]any{
			"token": testToken, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions":  map[string]string{"contents": "read", "metadata": "read"},
			"repositories": []map[string]string{{"full_name": testRepo}},
		}
	}
	f.archive = a
}

func (f *fakeGHES) serveTarball(w http.ResponseWriter, r *http.Request) {
	f.checkToken(r)
	a := f.archive
	a.mu.Lock()
	a.queries = append(a.queries, r.URL.Path)
	a.mu.Unlock()
	if a.apiCode != 0 {
		writeJSON(w, a.apiCode, map[string]string{"message": "no"})
		return
	}
	loc := f.srv.URL + "/_codeload/acme/app/legacy.tar.gz/" + r.PathValue("sha") + "?token=" + archiveCode
	if a.redirect != nil {
		loc = a.redirect(f.srv.URL)
	}
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

func (f *fakeGHES) serveCodeload(w http.ResponseWriter, r *http.Request) {
	a := f.archive
	a.mu.Lock()
	a.auths = append(a.auths, r.Header.Get("Authorization"))
	a.mu.Unlock()
	if r.URL.Query().Get("token") != archiveCode {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if a.dlCode == dropConnection {
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	if a.dlCode != 0 {
		w.WriteHeader(a.dlCode)
		return
	}
	if !a.chunked {
		w.Header().Set("Content-Length", fmt.Sprint(len(a.data)))
	}
	_, _ = w.Write(a.data)
}

func tarballDest(t *testing.T) string { return filepath.Join(t.TempDir(), "src") }

// The tarball of the exact commit is fetched with one token scoped to the
// repository, contents:read only, revoked after the download; the archive
// host gets no installation token.
func TestFetchTarball(t *testing.T) {
	f := newFakeGHES(t)
	a := &fakeArchive{data: archive(t, testHead, file("Dockerfile", "FROM scratch\n"))}
	f.withArchive(t, a)
	dest := tarballDest(t)
	if err := f.client(t, nil).FetchTarball(context.Background(), testRepo, testHead, dest, 1<<20); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "Dockerfile")); err != nil || string(got) != "FROM scratch\n" {
		t.Fatalf("Dockerfile = %q, %v", got, err)
	}
	if !slices.Equal(a.queries, []string{"/api/v3/repos/acme/app/tarball/" + testHead}) {
		t.Fatalf("tarball API calls %v", a.queries)
	}
	if len(a.auths) != 1 || a.auths[0] != "" {
		t.Fatalf("archive downloads carried Authorization %q", a.auths)
	}
	if len(f.minted) != 1 || !slices.Equal(f.minted[0].Repositories, []string{"app"}) ||
		len(f.minted[0].Permissions) != 1 || f.minted[0].Permissions["contents"] != "read" {
		t.Fatalf("token requests %+v, want one for app with contents:read", f.minted)
	}
	if f.revoked.Load() != 1 {
		t.Fatalf("revoked %d tokens, want 1", f.revoked.Load())
	}
}

// Fail closed: a redirect off GHES, a downgrade, user info, a non-redirect
// reply, a failed or oversized download, an archive of another commit, or
// a second redirect fetch nothing; the token is revoked anyway, and the
// archive URL's credential appears in no error.
func TestFetchTarballRefuses(t *testing.T) {
	big := archive(t, testHead, file("Dockerfile", strings.Repeat("x", 64<<10)))
	for name, a := range map[string]*fakeArchive{
		"redirect off GHES": {redirect: func(string) string { return "https://evil.example/archive?token=" + archiveCode }},
		"redirect over http": {redirect: func(base string) string {
			return strings.Replace(base, "https", "http", 1) + "/_codeload/x?token=" + archiveCode
		}},
		"redirect user info": {redirect: func(base string) string {
			return strings.Replace(base, "https://", "https://u:p@", 1) + "/_codeload/x?token=" + archiveCode
		}},
		"redirect other port": {redirect: func(base string) string { return base + "1/_codeload/x?token=" + archiveCode }},
		"no redirect":         {apiCode: http.StatusOK},
		"API refusal":         {apiCode: http.StatusNotFound},
		"download fails":      {dlCode: http.StatusNotFound},
		"length above cap":    {data: big},
		"stream above cap":    {data: big, chunked: true},
		"another commit":      {data: archive(t, strings.Repeat("e", 40), file("Dockerfile", "FROM scratch\n"))},
		"padding above cap":   {data: append(archive(t, testHead, file("Dockerfile", "FROM scratch\n")), make([]byte, 40<<10)...), chunked: true},
		"connection dropped":  {dlCode: dropConnection},
		"second redirect":     {redirect: func(base string) string { return base + "/_redirect?token=" + archiveCode }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGHES(t)
			f.withArchive(t, a)
			dest := tarballDest(t)
			err := f.client(t, nil).FetchTarball(context.Background(), testRepo, testHead, dest, 32<<10)
			if err == nil {
				t.Fatal("fetched")
			}
			if strings.Contains(err.Error(), archiveCode) || strings.Contains(err.Error(), testToken) {
				t.Fatalf("error quotes a credential: %v", err)
			}
			if f.revoked.Load() != 1 || len(a.queries) != 1 {
				t.Fatalf("revoked %d tokens, %d tarball calls; want 1 and 1 (refused for the case, not before): %v", f.revoked.Load(), len(a.queries), err)
			}
			if strings.HasPrefix(name, "redirect") || strings.Contains(name, "API") || name == "no redirect" {
				if len(a.auths) != 0 {
					t.Fatalf("downloaded %d times after a refused redirect", len(a.auths))
				}
			}
		})
	}
}

// Invalid input is refused before any call.
func TestFetchTarballValidatesInput(t *testing.T) {
	f := newFakeGHES(t)
	f.withArchive(t, &fakeArchive{})
	c := f.client(t, nil)
	for name, args := range map[string][2]string{
		"branch":    {testRepo, "main"},
		"short sha": {testRepo, "0123456"},
		"bad repo":  {"acme/../app", testHead},
	} {
		if err := c.FetchTarball(context.Background(), args[0], args[1], tarballDest(t), 1<<20); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := c.FetchTarball(context.Background(), testRepo, testHead, tarballDest(t), 0); err == nil {
		t.Error("a zero cap accepted")
	}
	if len(f.minted) != 0 {
		t.Fatalf("%d tokens minted for refused input", len(f.minted))
	}
}

// The default https port is the same port, named or not.
func TestAllowedArchiveURLDefaultPort(t *testing.T) {
	c := &Client{api: "https://ghes.example.internal/api/v3"}
	for raw, ok := range map[string]bool{
		"https://ghes.example.internal/_codeload/x":               true,
		"https://ghes.example.internal:443/_codeload/x":           true,
		"https://codeload.ghes.example.internal:443/x":            true,
		"https://ghes.example.internal:8443/_codeload/x":          false,
		"https://codeload.ghes.example.internal:8443/_codeload/x": false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.allowedArchiveURL(u) == nil; got != ok {
			t.Errorf("%s allowed = %v, want %v", raw, got, ok)
		}
	}
}

func TestAllowedArchiveURL(t *testing.T) {
	c := &Client{api: "https://ghes.example.internal:8443/api/v3"}
	for raw, ok := range map[string]bool{
		"https://ghes.example.internal:8443/_codeload/a/b/legacy.tar.gz/x?token=t": true,
		"https://codeload.ghes.example.internal:8443/a/b/legacy.tar.gz/x?token=t":  true,
		"https://GHES.example.internal:8443/x":                                     true,
		"https://ghes.example.internal/x":                                          false,
		"https://ghes.example.internal:443/x":                                      false,
		"http://ghes.example.internal:8443/x":                                      false,
		"https://user@ghes.example.internal:8443/x":                                false,
		"https://ghes.example.internal.evil:8443/x":                                false,
		"https://evilghes.example.internal:8443/x":                                 false,
		"https://codeload.evil.example:8443/x":                                     false,
		"https://codeload.codeload.ghes.example.internal:8443/x":                   false,
		"https://xcodeload.ghes.example.internal:8443/x":                           false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.allowedArchiveURL(u) == nil; got != ok {
			t.Errorf("%s allowed = %v, want %v", raw, got, ok)
		}
	}
}

// fakeGit puts a git on PATH that records each argument vector, one per
// line, and fails nothing.
func fakeGit(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return log
}

// The git fallback fetches exactly the commit at depth 1 by its SHA and
// checks out what it fetched: the argument vectors git receives contain
// --depth=1 and the SHA, never --unshallow, a branch, a tag or a refspec.
func TestFetchRepositoryArgumentVectors(t *testing.T) {
	log := fakeGit(t)
	if err := FetchRepository(context.Background(), "https://git.example.internal/acme/app.git", testHead, filepath.Join(t.TempDir(), "src")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{
		"init",
		"remote add origin https://git.example.internal/acme/app.git",
		"fetch --depth=1 origin " + testHead,
		"checkout FETCH_HEAD",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("git argv =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	fetch := gitCommands("https://git.example.internal/acme/app.git", testHead)[2]
	if !slices.Contains(fetch, "--depth=1") || !slices.Contains(fetch, testHead) {
		t.Fatalf("fetch argv %q lacks --depth=1 or the SHA", fetch)
	}
	for _, args := range gitCommands("https://git.example.internal/acme/app.git", testHead) {
		for _, a := range args {
			if strings.Contains(a, "unshallow") || strings.HasPrefix(a, "refs/") || strings.Contains(a, ":") && a != "https://git.example.internal/acme/app.git" ||
				a == "--tags" || a == "main" || a == "master" || a == "HEAD" || strings.HasPrefix(a, "--branch") || strings.HasPrefix(a, "--depth=") && a != "--depth=1" {
				t.Fatalf("git argv %q holds %q", args, a)
			}
		}
	}
}

// Anything but a full SHA (a branch, a ref, an option) is refused before
// git runs.
func TestFetchRepositoryRefusesNonSHA(t *testing.T) {
	log := fakeGit(t)
	for _, ref := range []string{"main", "refs/heads/main", "--upload-pack=sh", "0123456", testHead + "0"} {
		dest := filepath.Join(t.TempDir(), "src")
		if err := FetchRepository(context.Background(), "https://git.example.internal/acme/app.git", ref, dest); err == nil {
			t.Errorf("ref %q accepted", ref)
		}
	}
	if _, err := os.Stat(log); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("git ran for a refused ref")
	}
}

// The fetcher downloads the tarball with an App, and falls back to git
// without one.
func TestFetcherChoosesTheTransport(t *testing.T) {
	if _, err := NewFetcher(nil, 0); err == nil {
		t.Fatal("a zero cap accepted")
	}
	f := newFakeGHES(t)
	a := &fakeArchive{data: archive(t, testHead, file("Dockerfile", "FROM scratch\n"))}
	f.withArchive(t, a)
	withApp, err := NewFetcher(f.client(t, nil), 1<<20)
	if err != nil || !withApp.Tarball() {
		t.Fatalf("fetcher with an App: %v, tarball %v", err, withApp != nil && withApp.Tarball())
	}
	if err := withApp.Fetch(context.Background(), testRepo, "file:///nowhere", testHead, tarballDest(t)); err != nil || len(a.queries) != 1 {
		t.Fatalf("fetch with an App = %v, %d tarball calls", err, len(a.queries))
	}

	log := fakeGit(t)
	fallback, err := NewFetcher(nil, 1<<20)
	if err != nil || fallback.Tarball() {
		t.Fatalf("fetcher without an App: %v", err)
	}
	if err := fallback.Fetch(context.Background(), testRepo, "https://git.example.internal/acme/app.git", testHead, tarballDest(t)); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(log); err != nil || !strings.Contains(string(raw), "fetch --depth=1 origin "+testHead) {
		t.Fatalf("git fallback argv %q, %v", raw, err)
	}
}
