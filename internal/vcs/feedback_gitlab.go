package vcs

// GitLab feedback (V1.1 spec 3.3): the commit status and the sticky note on
// the merge request, written with the access token. The token needs the api
// scope and the Developer role for it; without them GitLab refuses the
// write, an error the caller logs: the deploy never depends on it.

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

// SetCommitStatus implements Provider: POST /projects/:id/statuses/:sha in
// the name "previewd". GitLab spells failure "failed".
func (g *GitLab) SetCommitStatus(ctx context.Context, projectID, commitSHA, state, targetURL, description string) error {
	if err := validate.GitLabProjectID(projectID); err != nil {
		return err
	}
	if err := checkStatus(commitSHA, state, targetURL, description); err != nil {
		return err
	}
	glState := state
	if state == StateFailure {
		glState = "failed"
	}
	body, err := json.Marshal(struct {
		State       string `json:"state"`
		Name        string `json:"name"`
		TargetURL   string `json:"target_url,omitempty"`
		Description string `json:"description"`
	}{glState, statusContext, targetURL, description})
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	path := "/projects/" + projectID + "/statuses/" + commitSHA
	if err := g.send(ctx, http.MethodPost, path, body, http.StatusCreated, nil); err != nil {
		return fmt.Errorf("set %s status of project %s@%s: %w", state, projectID, commitSHA, err)
	}
	return nil
}

// send performs one write, requires status want and decodes at most
// maxReplyBytes of the reply into v.
func (g *GitLab) send(ctx context.Context, method, path string, body []byte, want int, v any) error {
	resp, err := g.do(ctx, g.http, method, path, body)
	if err != nil {
		return err
	}
	return decodeReply(resp, method, path, want, maxReplyBytes, v)
}

// mrNote is the part of a note of GET .../merge_requests/:iid/notes used.
type mrNote struct {
	ID     int64  `json:"id"`
	Body   string `json:"body"`
	System bool   `json:"system"`
	Author struct {
		ID int64 `json:"id"`
	} `json:"author"`
}

// PostComment implements Provider: the sticky note of the merge request.
// The note is the one the token's own account wrote (GET /user), a user note
// that starts with the marker; a note of anyone else, or a system note, is
// never taken for it, and never edited.
func (g *GitLab) PostComment(ctx context.Context, projectID, mrIID, body string) error {
	if err := checkComment(body); err != nil {
		return err
	}
	iid, base, err := glIDs(projectID, mrIID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Body string `json:"body"`
	}{body})
	if err != nil {
		return fmt.Errorf("encode note: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if err := g.postNote(ctx, base+"/merge_requests/"+mrIID+"/notes", body, payload); err != nil {
		return fmt.Errorf("post note on project %s!%d: %w", projectID, iid, err)
	}
	return nil
}

func (g *GitLab) postNote(ctx context.Context, notes, body string, payload []byte) error {
	var me struct {
		ID int64 `json:"id"`
	}
	if err := g.get(ctx, "/user", maxReplyBytes, &me); err != nil {
		return err
	}
	if me.ID < 1 {
		return fmt.Errorf("the token's account is not named: no note is its own")
	}
	existing, found, err := g.findNote(ctx, notes, me.ID)
	switch {
	case err != nil:
		return err
	case !found:
		return g.send(ctx, http.MethodPost, notes, payload, http.StatusCreated, nil)
	case strings.ReplaceAll(existing.Body, "\r\n", "\n") == body:
		return nil // unchanged: nothing to write
	}
	return g.send(ctx, http.MethodPut, notes+"/"+strconv.FormatInt(existing.ID, 10), payload, http.StatusOK, nil)
}

// findNote returns the sticky note of account self, searching at most
// maxCommentPages pages.
func (g *GitLab) findNote(ctx context.Context, notes string, self int64) (mrNote, bool, error) {
	for page := 1; page <= maxCommentPages; page++ {
		var batch []mrNote
		q := url.Values{"per_page": {strconv.Itoa(commentsPerPage)}, "page": {strconv.Itoa(page)}, "sort": {"asc"}}
		if err := g.get(ctx, notes+"?"+q.Encode(), maxCommentsReply, &batch); err != nil {
			return mrNote{}, false, err
		}
		for _, n := range batch {
			if !n.System && n.ID > 0 && n.Author.ID == self && strings.HasPrefix(n.Body, CommentMarker) {
				return n, true, nil
			}
		}
		if len(batch) < commentsPerPage {
			return mrNote{}, false, nil
		}
	}
	return mrNote{}, false, fmt.Errorf("more than %d notes: the sticky note is not searched for further", maxCommentPages*commentsPerPage)
}
