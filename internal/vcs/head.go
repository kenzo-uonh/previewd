package vcs

// The head of a pull or merge request as the forge reports it now (V1.2
// spec 3.4): what a CI trigger deploys. A trigger carries a project and a
// number, nothing else; the branch, the commit, the head project, the author
// and the clone URL are read from the forge, never taken from the caller.
// Who may deploy it is decided later, as for a webhook, by the deploy gate
// reading the forge again.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// Head is a request's head now. Every field has passed its validator.
type Head struct {
	Open bool
	Ref  string // the head branch
	SHA  string
	// HeadProject is the project the head lives in, as the forge spells it;
	// "" once it was deleted.
	HeadProject string
	CloneURL    string
	Author      Account
}

func (h Head) check() error {
	for _, err := range []error{validate.GitRef(h.Ref), validate.CommitSHA(h.SHA), validate.CloneURL(h.CloneURL)} {
		if err != nil {
			return err
		}
	}
	return nil
}

// PullRequestHead reads the head of pull request number of repo with one
// token (pull_requests:read), revoked before it returns.
func (c *Client) PullRequestHead(ctx context.Context, repo string, number uint32) (Head, error) {
	path, err := repoPath(repo)
	if err != nil {
		return Head{}, err
	}
	if number == 0 {
		return Head{}, errors.New("pull request number must be positive")
	}
	var h Head
	err = c.withToken(ctx, repo, func(ctx context.Context, bearer string) error {
		var pr pullRequestReply
		if err := c.get(ctx, bearer, path+"/pulls/"+strconv.FormatUint(uint64(number), 10), maxPRReplyBytes, &pr); err != nil {
			return err
		}
		var st PRState
		if err := st.fill(pr, repo, number); err != nil {
			return err
		}
		h = Head{Open: st.Open, Ref: pr.Head.Ref, SHA: st.HeadSHA, HeadProject: st.HeadRepo, CloneURL: pr.Base.Repo.CloneURL, Author: st.Opener}
		return h.check()
	}, "pull_requests")
	if err != nil {
		return Head{}, fmt.Errorf("read the head of %s#%d: %w", repo, number, err)
	}
	return h, nil
}

// PullRequestHead reads the head of pull request number of repo.
func (f *Forgejo) PullRequestHead(ctx context.Context, repo string, number uint32) (Head, error) {
	path, err := forgejoRepoPath(repo)
	if err != nil {
		return Head{}, err
	}
	if number == 0 {
		return Head{}, errors.New("pull request number must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var pr fjPullReply
	if err := f.get(ctx, path+"/pulls/"+strconv.FormatUint(uint64(number), 10), maxPRReplyBytes, &pr); err != nil {
		return Head{}, fmt.Errorf("read the head of %s#%d: %w", repo, number, err)
	}
	st, err := f.state(pr, repo, number)
	if err != nil {
		return Head{}, fmt.Errorf("read the head of %s#%d: %w", repo, number, err)
	}
	if pr.Head.Ref == nil || pr.Base.Repo.CloneURL == nil {
		return Head{}, fmt.Errorf("read the head of %s#%d: the reply is incomplete", repo, number)
	}
	h := Head{Open: st.Open, Ref: *pr.Head.Ref, SHA: st.HeadSHA, HeadProject: st.HeadRepo, CloneURL: *pr.Base.Repo.CloneURL, Author: st.Opener}
	if err := h.check(); err != nil {
		return Head{}, fmt.Errorf("read the head of %s#%d: %w", repo, number, err)
	}
	return h, nil
}

// PullRequestHead reads the head of merge request number of the project at
// path (path_with_namespace). The project is resolved by its path and must
// still be at it; a fork's path is read from the fork, and a fork GitLab no
// longer has is a deleted head ("").
func (g *GitLab) PullRequestHead(ctx context.Context, path string, number uint32) (Head, error) {
	if err := validate.GitLabProjectPath(path); err != nil {
		return Head{}, fmt.Errorf("read the head of %s: %w", validate.Quote(path), err)
	}
	if number == 0 {
		return Head{}, errors.New("merge request iid must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	h, err := g.head(ctx, path, number)
	if err != nil {
		return Head{}, fmt.Errorf("read the head of %s!%d: %w", path, number, err)
	}
	return h, nil
}

func (g *GitLab) head(ctx context.Context, path string, number uint32) (Head, error) {
	p, err := g.project(ctx, url.PathEscape(path))
	if err != nil {
		return Head{}, err
	}
	if p.Path != path {
		return Head{}, errors.New("the project reply is not about that project")
	}
	id := strconv.FormatInt(p.ID, 10)
	var mr glMergeRequestReply
	if err := g.get(ctx, "/projects/"+id+"/merge_requests/"+strconv.FormatUint(uint64(number), 10), maxMRReplyBytes, &mr); err != nil {
		return Head{}, err
	}
	st, err := g.state(mr, id, number)
	if err != nil {
		return Head{}, err
	}
	if mr.SourceBranch == nil {
		return Head{}, errors.New("the reply names no source branch")
	}
	h := Head{Open: st.Open, Ref: *mr.SourceBranch, SHA: st.HeadSHA, CloneURL: p.CloneURL, Author: st.Author}
	switch {
	case mr.SourceProjectID == nil:
	case *mr.SourceProjectID == p.ID:
		h.HeadProject = path
	default:
		if h.HeadProject, err = g.forkPath(ctx, *mr.SourceProjectID); err != nil {
			return Head{}, err
		}
	}
	if err := h.check(); err != nil {
		return Head{}, err
	}
	return h, nil
}

// forkPath is the path of the fork id, "" when GitLab no longer has it.
func (g *GitLab) forkPath(ctx context.Context, id int64) (string, error) {
	if id < 1 {
		return "", fmt.Errorf("invalid source project id %d", id)
	}
	resp, err := g.request(ctx, g.http, "/projects/"+strconv.FormatInt(id, 10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return "", nil
	}
	var p struct {
		ID   *int64  `json:"id"`
		Path *string `json:"path_with_namespace"`
	}
	if err := decodeReply(resp, http.MethodGet, "/projects/"+strconv.FormatInt(id, 10), http.StatusOK, maxProjectReplyBytes, &p); err != nil {
		return "", err
	}
	if p.ID == nil || p.Path == nil || *p.ID != id || validate.GitLabProjectPath(*p.Path) != nil {
		return "", fmt.Errorf("the reply is not about source project %d", id)
	}
	return *p.Path, nil
}
