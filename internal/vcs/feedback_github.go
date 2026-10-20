package vcs

// GitHub feedback (V1.1 spec 3.3): the commit status and the sticky comment,
// written as the GitHub App. Each write mints a token scoped to the one
// repository and the one permission it needs, at write level (statuses for
// the status, pull_requests for the comment), and revokes it before it
// returns. An App installed without those permissions gets a refused write,
// an error the caller logs: the deploy never depends on it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// commentsPerPage is the largest page GitHub serves; maxCommentPages
	// bounds the search for the sticky comment: a thread longer than that
	// is an error, never an unbounded read or a second comment.
	commentsPerPage = 100
	maxCommentPages = 10
	// maxCommentsReply bounds one page: 100 comments of at most 64 KiB.
	maxCommentsReply = 8 << 20
)

// SetCommitStatus implements Provider: POST /repos/{owner}/{repo}/statuses/{sha}
// in the context "previewd". GitHub names the three states as previewd does.
func (c *Client) SetCommitStatus(ctx context.Context, projectID, commitSHA, state, targetURL, description string) error {
	if err := checkStatus(commitSHA, state, targetURL, description); err != nil {
		return err
	}
	repoAPI, err := repoPath(projectID)
	if err != nil {
		return err
	}
	in := struct {
		State       string `json:"state"`
		TargetURL   string `json:"target_url,omitempty"`
		Description string `json:"description"`
		Context     string `json:"context"`
	}{state, targetURL, description, statusContext}
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	err = c.withToken(ctx, projectID, func(ctx context.Context, bearer string) error {
		return c.call(ctx, http.MethodPost, bearer, repoAPI+"/statuses/"+commitSHA, body, http.StatusCreated, maxReplyBytes, nil)
	}, "statuses:write")
	if err != nil {
		return fmt.Errorf("set %s status of %s@%s: %w", state, projectID, commitSHA, err)
	}
	return nil
}

// issueComment is the part of a comment of GET /repos/{o}/{r}/issues/{n}/comments used.
type issueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	// App is set when a GitHub App wrote the comment: only the comments of
	// previewd's own App are ever taken for its sticky comment.
	App *struct {
		ID int64 `json:"id"`
	} `json:"performed_via_github_app"`
}

// PostComment implements Provider. A pull request's comments are the issue
// comments of its number.
func (c *Client) PostComment(ctx context.Context, projectID, mrIID, body string) error {
	if err := checkComment(body); err != nil {
		return err
	}
	number, err := validate.MergeRequestIID(mrIID)
	if err != nil {
		return err
	}
	repoAPI, err := repoPath(projectID)
	if err != nil {
		return err
	}
	issue := repoAPI + "/issues/" + strconv.FormatUint(uint64(number), 10)
	payload, err := json.Marshal(struct {
		Body string `json:"body"`
	}{body})
	if err != nil {
		return fmt.Errorf("encode comment: %w", err)
	}
	err = c.withToken(ctx, projectID, func(ctx context.Context, bearer string) error {
		existing, found, err := c.findComment(ctx, bearer, issue)
		switch {
		case err != nil:
			return err
		case !found:
			return c.call(ctx, http.MethodPost, bearer, issue+"/comments", payload, http.StatusCreated, maxReplyBytes, nil)
		case strings.ReplaceAll(existing.Body, "\r\n", "\n") == body:
			return nil // unchanged: nothing to write
		}
		return c.call(ctx, http.MethodPatch, bearer, repoAPI+"/issues/comments/"+strconv.FormatInt(existing.ID, 10),
			payload, http.StatusOK, maxReplyBytes, nil)
	}, "pull_requests:write")
	if err != nil {
		return fmt.Errorf("post comment on %s#%d: %w", projectID, number, err)
	}
	return nil
}

// findComment returns the comment of the thread that starts with the marker
// and was written by this App.
func (c *Client) findComment(ctx context.Context, bearer, issue string) (issueComment, bool, error) {
	for page := 1; page <= maxCommentPages; page++ {
		var comments []issueComment
		q := url.Values{"per_page": {strconv.Itoa(commentsPerPage)}, "page": {strconv.Itoa(page)}}
		if err := c.get(ctx, bearer, issue+"/comments?"+q.Encode(), maxCommentsReply, &comments); err != nil {
			return issueComment{}, false, err
		}
		for _, cm := range comments {
			if cm.App != nil && cm.App.ID == c.appID && cm.ID > 0 && strings.HasPrefix(cm.Body, CommentMarker) {
				return cm, true, nil
			}
		}
		if len(comments) < commentsPerPage {
			return issueComment{}, false, nil
		}
	}
	return issueComment{}, false, fmt.Errorf("more than %d comments: the sticky comment is not searched for further", maxCommentPages*commentsPerPage)
}
