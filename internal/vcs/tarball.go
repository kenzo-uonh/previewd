package vcs

// Source fetch (V1 spec H2, V1-I11). With a GitHub App, the source of a
// commit is the commit's tarball, downloaded from GHES with an installation
// token scoped to the one repository, contents:read only, revoked after the
// download. The archive is streamed, never trusted: it is extracted entry by
// entry under the build directory through an os.Root, and every entry that
// could reach outside it (an absolute path, "..", a link leaving the tree, a
// hard link, a device) or exceed the bounds is refused, never skipped. The
// caller then packs that directory into the build context
// (orchestrator.PrepareBuildContext), which checks every symlink again and
// runs the Dockerfile preflight. Without an App, git fetch --depth=1 of the
// exact commit (FetchRepository) is the fallback.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/kenzo-uonh/previewd/internal/textutil"
	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// fetchTimeout bounds one source fetch: the token, the redirect and the
	// whole download and extraction.
	fetchTimeout = 10 * time.Minute
	// maxTarEntries bounds the entries of one archive; maxEntryName the
	// length of one entry's name.
	maxTarEntries = 100_000
	maxEntryName  = 4096
	// maxRedirectBytes bounds the API reply that carries the redirect.
	maxRedirectBytes = 64 << 10
	// codeloadPrefix names the host GHES serves archives from under subdomain
	// isolation (codeload.<GHES host>).
	codeloadPrefix = "codeload."
)

// ErrUnsafeArchive is an archive entry refused by the extraction.
var ErrUnsafeArchive = errors.New("unsafe source archive")

// Fetcher fetches the source of one commit into a directory: the commit
// tarball from GHES when a GitHub App is configured, git fetch --depth=1
// only when none is.
type Fetcher struct {
	client   *Client
	maxBytes int64
}

// NewFetcher returns the fetcher of the daemon. client is the GHES client of
// the GitHub App, nil when none is configured (git fallback); maxBytes
// (PREVIEWD_MAX_BUILD_CONTEXT_MIB) bounds both the compressed archive and
// the bytes it extracts.
func NewFetcher(client *Client, maxBytes int64) (*Fetcher, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("source fetch: size cap must be positive, got %d", maxBytes)
	}
	return &Fetcher{client: client, maxBytes: maxBytes}, nil
}

// Tarball reports whether the fetcher downloads tarballs from GHES.
func (f *Fetcher) Tarball() bool { return f.client != nil }

// Fetch writes the tree of commitSHA of repo into destDir, which must not
// exist yet.
func (f *Fetcher) Fetch(ctx context.Context, repo, cloneURL, commitSHA, destDir string) error {
	if f.client == nil {
		return FetchRepository(ctx, cloneURL, commitSHA, destDir)
	}
	return f.client.FetchTarball(ctx, repo, commitSHA, destDir, f.maxBytes)
}

// FetchTarball downloads the tarball of commitSHA of repo (GET
// /repos/{owner}/{repo}/tarball/{sha}) and extracts it into destDir, which
// it creates. The installation token is scoped to repo with contents:read
// and revoked before it returns. The API answers with a redirect to the
// archive, which carries its own short-lived credential: it is followed
// only to the GHES host itself or to codeload.<GHES host> over https, and
// the installation token is never sent there. The redirect URL is never
// logged or quoted in an error. maxBytes bounds the compressed archive and
// the bytes it extracts; the whole fetch is bounded by fetchTimeout.
func (c *Client) FetchTarball(ctx context.Context, repo, commitSHA, destDir string, maxBytes int64) error {
	repoAPI, err := repoPath(repo)
	if err != nil {
		return err
	}
	if err := validate.CommitSHA(commitSHA); err != nil {
		return fmt.Errorf("fetch %s: %w", repo, err)
	}
	if maxBytes <= 0 {
		return fmt.Errorf("fetch %s: size cap must be positive, got %d", repo, maxBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	mctx, mcancel := context.WithTimeout(ctx, readTimeout)
	tok, err := c.mint(mctx, repo, "contents")
	mcancel()
	if err != nil {
		return fmt.Errorf("fetch %s@%s: %w", repo, commitSHA, err)
	}
	defer c.revoke(ctx, tok)

	archive, err := c.archiveURL(ctx, tok.value, repoAPI+"/tarball/"+commitSHA)
	if err != nil {
		return fmt.Errorf("fetch %s@%s: %w", repo, commitSHA, err)
	}
	if err := c.download(ctx, archive, commitSHA, destDir, maxBytes); err != nil {
		return fmt.Errorf("fetch %s@%s: %w", repo, commitSHA, err)
	}
	return nil
}

// archiveURL asks the API for the archive and returns where it is served:
// the redirect target, checked by allowedArchiveURL.
func (c *Client) archiveURL(ctx context.Context, bearer, apiPath string) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api+apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("GET %s: build request: %w", apiPath, err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", apiPath, err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRedirectBytes))
	if closeErr := resp.Body.Close(); readErr == nil {
		readErr = closeErr
	}
	switch {
	case readErr != nil:
		return nil, fmt.Errorf("GET %s: read reply: %w", apiPath, readErr)
	case resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusTemporaryRedirect:
		return nil, fmt.Errorf("GET %s: HTTP %d, want a redirect to the archive: %q", apiPath, resp.StatusCode,
			textutil.Truncate(strings.TrimSpace(string(raw)), maxQuotedReply))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("GET %s: malformed redirect", apiPath)
	}
	if !loc.IsAbs() {
		loc = req.URL.ResolveReference(loc)
	}
	if err := c.allowedArchiveURL(loc); err != nil {
		return nil, fmt.Errorf("GET %s: %w", apiPath, err)
	}
	return loc, nil
}

// allowedArchiveURL accepts an https URL without user info on the GHES host
// and port, or on codeload.<GHES host> with the same port.
func (c *Client) allowedArchiveURL(u *url.URL) error {
	api, err := url.Parse(c.api)
	if err != nil {
		return fmt.Errorf("GHES URL: %w", err)
	}
	if u.Scheme != "https" || u.User != nil || u.Host == "" {
		return errors.New("redirect to the archive is not a plain https URL")
	}
	host, port := u.Hostname(), httpsPort(u)
	ghesHost, ghesPort := api.Hostname(), httpsPort(api)
	if port != ghesPort || (!strings.EqualFold(host, ghesHost) && !strings.EqualFold(host, codeloadPrefix+ghesHost)) {
		return fmt.Errorf("redirect to the archive leaves GHES (host %q)", textutil.Truncate(net.JoinHostPort(host, port), 255))
	}
	return nil
}

// httpsPort is u's port, 443 when it names none.
func httpsPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}

// download streams the archive at u into extractTarball. The request
// carries no credential of previewd's: u holds its own.
func (c *Client) download(ctx context.Context, u *url.URL, commitSHA, destDir string, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("download the archive: build request")
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.dl.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // the URL carries a credential: never quote it
		}
		return fmt.Errorf("download the archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("download the archive: HTTP %d", resp.StatusCode)
	case resp.ContentLength > maxBytes:
		return fmt.Errorf("download the archive: %d bytes, above the %d-byte cap", resp.ContentLength, maxBytes)
	}
	body := &cappedReader{r: resp.Body, left: maxBytes}
	if err := extractTarball(body, commitSHA, destDir, maxBytes, maxTarEntries); err != nil {
		return err
	}
	// The rest of the stream (gzip trailer, padding) is read to the cap.
	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("download the archive: %w", err)
	}
	return nil
}

// cappedReader fails once more than left bytes were read: an archive
// above the cap is refused, never cut.
type cappedReader struct {
	r    io.Reader
	left int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, fmt.Errorf("%w: the compressed archive exceeds the cap", ErrUnsafeArchive)
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, fmt.Errorf("%w: the compressed archive exceeds the cap", ErrUnsafeArchive)
	}
	return n, err
}

func unsafeEntry(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnsafeArchive}, args...)...)
}

func quoteName(name string) string { return fmt.Sprintf("%q", textutil.Truncate(name, 256)) }

// extractTarball extracts the gzip-compressed tar r, as GitHub and git
// archive write it, into destDir, which it creates (0750), through an
// os.Root. The archive must open with a pax global header whose comment is
// commitSHA (the commit the archive was made from), and every other entry
// must sit under one top-level directory, which is stripped. Directories,
// regular files (mode 0644, or 0755 if any execute bit was set) and
// symlinks whose relative target stays inside the tree are written; any
// other entry, an absolute or non-clean name, "..", a duplicate, more than
// maxEntries entries or more than maxBytes of file content is an error, and
// nothing of the archive is trusted.
func extractTarball(r io.Reader, commitSHA, destDir string, maxBytes int64, maxEntries int) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: not gzip: %w", ErrUnsafeArchive, err)
	}
	defer func() { _ = gz.Close() }()
	gz.Multistream(false)
	if err := os.Mkdir(destDir, 0o750); err != nil {
		return fmt.Errorf("create source directory: %w", err)
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return fmt.Errorf("open source directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(gz)
	var (
		prefix   string
		commitOK bool
		total    int64
		seen     = map[string]bool{}
	)
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: read entry: %w", ErrUnsafeArchive, err)
		}
		if n >= maxEntries {
			return unsafeEntry("more than %d entries", maxEntries)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			if n != 0 || hdr.PAXRecords["comment"] != commitSHA {
				return unsafeEntry("the archive is not of commit %s", commitSHA)
			}
			commitOK = true
			continue
		}
		if !commitOK {
			return unsafeEntry("no pax global header naming commit %s", commitSHA)
		}
		rel, err := entryPath(hdr.Name, &prefix)
		if err != nil {
			return err
		}
		if rel == "" {
			if hdr.Typeflag != tar.TypeDir {
				return unsafeEntry("top-level entry %s is not a directory", quoteName(hdr.Name))
			}
			continue
		}
		if seen[rel] {
			return unsafeEntry("%s appears twice", quoteName(rel))
		}
		seen[rel] = true
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.Mkdir(rel, 0o755); err != nil {
				return fmt.Errorf("extract %s: %w", quoteName(rel), err)
			}
		case tar.TypeReg:
			if hdr.Size < 0 || hdr.Size > maxBytes-total {
				return unsafeEntry("file content exceeds %d bytes at %s", maxBytes, quoteName(rel))
			}
			total += hdr.Size
			if err := writeEntry(root, rel, hdr, tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := linkInside(rel, hdr.Linkname); err != nil {
				return err
			}
			if err := root.Symlink(hdr.Linkname, rel); err != nil {
				return fmt.Errorf("extract %s: %w", quoteName(rel), err)
			}
		case tar.TypeLink:
			return unsafeEntry("hard link %s refused", quoteName(rel))
		default:
			return unsafeEntry("%s has type %q: only directories, files and symlinks are extracted", quoteName(rel), hdr.Typeflag)
		}
	}
	if !commitOK {
		return unsafeEntry("no pax global header naming commit %s", commitSHA)
	}
	return nil
}

// entryPath strips the archive's single top-level directory from name and
// returns the clean relative path under it ("" for that directory itself).
// prefix is set by the first entry.
func entryPath(name string, prefix *string) (string, error) {
	trimmed := strings.TrimSuffix(name, "/")
	switch {
	case len(name) > maxEntryName || strings.ContainsAny(name, "\x00\\"):
		return "", unsafeEntry("entry name %s", quoteName(name))
	case path.IsAbs(name):
		return "", unsafeEntry("absolute path %s", quoteName(name))
	case !fs.ValidPath(trimmed) || trimmed == ".":
		// fs.ValidPath: no empty, "." or ".." element, no leading or
		// trailing slash.
		return "", unsafeEntry("%s is not a clean relative path", quoteName(name))
	}
	top, rest, _ := strings.Cut(trimmed, "/")
	if *prefix == "" {
		*prefix = top
	}
	if top != *prefix {
		return "", unsafeEntry("%s is outside the archive's directory %s", quoteName(name), quoteName(*prefix))
	}
	return rest, nil
}

// linkInside refuses a symlink at rel whose target is absolute or, resolved
// lexically from rel's directory, leaves the tree. os.Root keeps every later
// write inside it as well.
func linkInside(rel, target string) error {
	if target == "" || len(target) > maxEntryName || strings.ContainsAny(target, "\x00\\") || path.IsAbs(target) {
		return unsafeEntry("symlink %s -> %s refused", quoteName(rel), quoteName(target))
	}
	resolved := path.Join(path.Dir(rel), target)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return unsafeEntry("symlink %s -> %s leaves the tree", quoteName(rel), quoteName(target))
	}
	return nil
}

// writeEntry creates rel, which must not exist, with exactly hdr.Size bytes
// of tr.
func writeEntry(root *os.Root, rel string, hdr *tar.Header, tr io.Reader) (err error) {
	mode := os.FileMode(0o644)
	if hdr.Mode&0o111 != 0 {
		mode = 0o755
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("extract %s: %w", quoteName(rel), err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("extract %s: %w", quoteName(rel), cerr)
		}
	}()
	if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
		return fmt.Errorf("%w: extract %s: %w", ErrUnsafeArchive, quoteName(rel), err)
	}
	return nil
}
