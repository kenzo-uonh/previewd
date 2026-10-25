package vcs

// GitLab source fetch (V1.1 spec 3.1): the source of a commit is the
// project's archive, streamed from
// GET /api/v4/projects/:id/repository/archive.tar.gz?sha=:commit with the
// access token in PRIVATE-TOKEN, and extracted entry by entry under the
// destination through an os.Root by extractTarball, the extraction the GHES
// tarball uses (tarball.go): git archive writes the same pax global header
// naming the commit, and the same bounds apply. GitLab serves the archive
// itself, with no redirect: one is refused, so the token cannot be carried to
// another host.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// FetchTarball implements Provider: it extracts the tree of commitSHA of the
// project projectID (its numeric ID) into destDir, which it creates.
// maxBytes bounds the compressed archive and the bytes it extracts; the
// whole fetch is bounded by fetchTimeout. The archive must be of commitSHA,
// else nothing of it is trusted.
func (g *GitLab) FetchTarball(ctx context.Context, projectID, commitSHA, destDir string, maxBytes int64) error {
	if err := validate.GitLabProjectID(projectID); err != nil {
		return fmt.Errorf("fetch project %s: %w", validate.Quote(projectID), err)
	}
	if err := validate.CommitSHA(commitSHA); err != nil {
		return fmt.Errorf("fetch project %s: %w", projectID, err)
	}
	if maxBytes <= 0 {
		return fmt.Errorf("fetch project %s: size cap must be positive, got %d", projectID, maxBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	path := "/projects/" + projectID + "/repository/archive.tar.gz?" + url.Values{"sha": {commitSHA}}.Encode()
	resp, err := g.request(ctx, g.dl, path)
	if err != nil {
		return fmt.Errorf("fetch project %s@%s: %w", projectID, commitSHA, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("fetch project %s@%s: download the archive: HTTP %d", projectID, commitSHA, resp.StatusCode)
	case resp.ContentLength > maxBytes:
		return fmt.Errorf("fetch project %s@%s: download the archive: %d bytes, above the %d-byte cap",
			projectID, commitSHA, resp.ContentLength, maxBytes)
	}
	body := &cappedReader{r: resp.Body, left: maxBytes}
	if err := extractTarball(body, commitSHA, destDir, maxBytes, maxTarEntries); err != nil {
		return fmt.Errorf("fetch project %s@%s: %w", projectID, commitSHA, err)
	}
	// The rest of the stream (gzip trailer, padding) is read to the cap.
	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("fetch project %s@%s: download the archive: %w", projectID, commitSHA, errors.Unwrap(err))
	}
	return nil
}

// GitLabFetcher fetches the source of a commit for the reconciler: the store
// keeps a project by its path, the archive endpoint wants its ID, so the path
// is resolved first, each time (a project renamed or deleted since is never
// fetched under its old name). No git runs for a merge request: the clone URL
// of a hook is not used.
type GitLabFetcher struct {
	gitlab   *GitLab
	maxBytes int64
}

// NewGitLabFetcher returns the fetcher of a GitLab deployment. maxBytes
// (PREVIEWD_MAX_BUILD_CONTEXT_MIB) bounds both the compressed archive and the
// bytes it extracts.
func NewGitLabFetcher(g *GitLab, maxBytes int64) (*GitLabFetcher, error) {
	switch {
	case g == nil:
		return nil, errors.New("source fetch: no GitLab driver")
	case maxBytes <= 0:
		return nil, fmt.Errorf("source fetch: size cap must be positive, got %d", maxBytes)
	}
	return &GitLabFetcher{gitlab: g, maxBytes: maxBytes}, nil
}

// Fetch writes the tree of commitSHA of the project at path repo into
// destDir, which must not exist yet. It has the shape of
// orchestrator.FetchFunc.
func (f *GitLabFetcher) Fetch(ctx context.Context, repo, _, commitSHA, destDir string) error {
	id, err := f.gitlab.ResolveProject(ctx, repo)
	if err != nil {
		return fmt.Errorf("fetch %s@%s: %w", repo, commitSHA, err)
	}
	return f.gitlab.FetchTarball(ctx, id, commitSHA, destDir, f.maxBytes)
}
