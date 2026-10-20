package vcs

// The GitLab driver (V1.1 spec 3.1): GitLab Self-Managed (CE/EE) and
// gitlab.com through REST API v4. previewd holds one Project or Group Access
// Token, read from a systemd credential into memory, sent in the
// PRIVATE-TOKEN header to the one configured host and nowhere else: no
// redirect is followed, so the header cannot be carried to another host.
// The token needs read_api and read_repository, nothing more, and previewd
// only reads.
//
// Like the GHES client: REST over net/http only (no SDK), HTTPS only, the
// site CA when one is configured, no proxy from the environment, every reply
// bounded and every call timed out. A reply that cannot be read completely
// and consistently is an error, never a default.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// gitlabAPIPrefix is the REST root of GitLab.
	gitlabAPIPrefix = "/api/v4"
	// gitlabTokenHeader carries the webhook's shared secret.
	gitlabTokenHeader = "X-Gitlab-Token" // #nosec G101 -- a header name, not a credential
	// EventMergeRequestHook is the X-Gitlab-Event of a merge request hook,
	// the only hook previewd acts on.
	EventMergeRequestHook = "Merge Request Hook"

	// maxMRReplyBytes bounds a merge request: its description is up to a
	// million characters, four bytes each at worst.
	maxMRReplyBytes = 8 << 20
	// maxProjectReplyBytes bounds a project: its settings run to some tens
	// of kilobytes.
	maxProjectReplyBytes = 1 << 20
	// gitlabDeveloper is the lowest access level that can push (Developer):
	// the counterpart of GitHub's write.
	gitlabDeveloper = 30
)

// GitLabConfig configures a GitLab driver. Token is the access token (held in
// memory only); CAPEM the site CA bundle, nil for the system roots.
type GitLabConfig struct {
	BaseURL string // PREVIEWD_GITLAB_URL: the https scheme, a host and an optional port
	Token   []byte
	CAPEM   []byte
	Logger  *slog.Logger
}

// GitLab reads GitLab as the holder of an access token.
type GitLab struct {
	api    string
	token  string
	http   *http.Client
	dl     *http.Client
	logger *slog.Logger
}

// NewGitLab validates the configuration. It makes no call.
func NewGitLab(cfg GitLabConfig) (*GitLab, error) {
	base, err := validate.GitLabURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if !validToken(string(cfg.Token)) {
		return nil, errors.New("GitLab token: want 1 to 255 printable characters without space")
	}
	transport, err := newTransport(cfg.CAPEM, "GitLab")
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &GitLab{
		api:   base + gitlabAPIPrefix,
		token: string(cfg.Token),
		http:  &http.Client{Timeout: callTimeout, Transport: transport, CheckRedirect: noRedirect},
		// Archive downloads last longer than one call: bounded by the
		// fetch's context instead, still without proxy or redirect.
		dl:     &http.Client{Transport: transport, CheckRedirect: noRedirect},
		logger: logger,
	}, nil
}

// Name implements Provider.
func (g *GitLab) Name() string { return ProviderGitLab }

// VerifyWebhook implements Provider. GitLab authenticates a hook with a
// shared secret it echoes in X-Gitlab-Token, not with a signature of the
// body: the secret is compared in constant time (subtle.ConstantTimeCompare
// over SHA-256 digests, so neither the content nor the length of the secret
// shows in the time taken) and the body is read only afterwards. Exactly one
// token header, never an empty secret. Because the body is not covered, the
// listener must be TLS (it is, unless PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS).
func (g *GitLab) VerifyWebhook(req *http.Request, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: %w", validate.ErrSignature, errNoSecret)
	}
	tokens := req.Header.Values(gitlabTokenHeader)
	if len(tokens) != 1 {
		return nil, fmt.Errorf("%w: want exactly one %s header", validate.ErrSignature, gitlabTokenHeader)
	}
	want, got := sha256.Sum256(secret), sha256.Sum256([]byte(tokens[0]))
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		return nil, fmt.Errorf("%w: token mismatch", validate.ErrSignature)
	}
	body, err := readWebhookBody(req)
	if err != nil {
		return nil, err
	}
	restoreBody(req, body)
	return body, nil
}

// glAccountWire is a GitLab user object.
type glAccountWire struct {
	ID       *int64  `json:"id"`
	Username *string `json:"username"`
}

func (a *glAccountWire) account(role string) (Account, error) {
	if a == nil || a.ID == nil || a.Username == nil {
		return Account{}, fmt.Errorf("%s: missing required field", role)
	}
	if err := validate.GitLabUsername(*a.Username); err != nil || *a.ID <= 0 {
		return Account{}, fmt.Errorf("%s: invalid account %s (id %d)", role, validate.Quote(*a.Username), *a.ID)
	}
	return Account{Login: *a.Username, ID: *a.ID}, nil
}

type glProjectWire struct {
	ID                *int64  `json:"id"`
	PathWithNamespace *string `json:"path_with_namespace"`
	GitHTTPURL        *string `json:"git_http_url"`
}

// mergeRequestHookWire is the part of a Merge Request Hook used.
type mergeRequestHookWire struct {
	ObjectKind *string        `json:"object_kind"`
	User       *glAccountWire `json:"user"`
	Project    *glProjectWire `json:"project"`
	Attributes *struct {
		IID             *uint32        `json:"iid"`
		Action          *string        `json:"action"`
		OldRev          *string        `json:"oldrev"`
		SourceBranch    *string        `json:"source_branch"`
		SourceProjectID *int64         `json:"source_project_id"`
		TargetProjectID *int64         `json:"target_project_id"`
		AuthorID        *int64         `json:"author_id"`
		UpdatedAt       *string        `json:"updated_at"`
		Source          *glProjectWire `json:"source"`
		LastCommit      *struct {
			ID *string `json:"id"`
		} `json:"last_commit"`
	} `json:"object_attributes"`
}

// ParseEvent implements Provider for a Merge Request Hook. The mapping to
// previewd's actions: open, reopen, close; merge is a close (the branch is
// done: tear down); update is a push only when the head moved (oldrev), any
// other update (title, description, labels) builds nothing; approved and
// approval are an approval, unapproved and unapproval its withdrawal. The
// head and the update time come from the signed-in-transit body; the
// author is named by ID only.
func (g *GitLab) ParseEvent(payload []byte) (*Event, error) {
	reject := func(format string, args ...any) (*Event, error) {
		return nil, fmt.Errorf("%w: %s", validate.ErrPayload, fmt.Sprintf(format, args...))
	}
	if len(payload) > validate.MaxPayloadBytes {
		return reject("body exceeds %d bytes", validate.MaxPayloadBytes)
	}
	var w mergeRequestHookWire
	if err := json.Unmarshal(payload, &w); err != nil {
		return reject("invalid JSON: %v", err)
	}
	if w.ObjectKind == nil {
		return reject("missing required field")
	}
	if *w.ObjectKind != "merge_request" {
		return nil, fmt.Errorf("%w: %s hook", validate.ErrIgnoredAction, validate.Quote(*w.ObjectKind))
	}
	ev, action, err := w.event()
	if err != nil {
		return reject("%v", err)
	}
	if ev.Action, err = glAction(action, w.Attributes.OldRev); err != nil {
		return nil, err
	}
	return ev, nil
}

// event validates the fields every action needs and returns the event with
// the forge's own action name.
func (w *mergeRequestHookWire) event() (*Event, string, error) {
	a, p := w.Attributes, w.Project
	if a == nil || p == nil || p.ID == nil || p.PathWithNamespace == nil || p.GitHTTPURL == nil ||
		a.IID == nil || a.Action == nil || a.SourceBranch == nil || a.TargetProjectID == nil ||
		a.AuthorID == nil || a.UpdatedAt == nil || a.LastCommit == nil || a.LastCommit.ID == nil {
		return nil, "", errors.New("missing required field")
	}
	sender, err := w.User.account("sender")
	if err != nil {
		return nil, "", err
	}
	ev := &Event{
		ProjectID: strconv.FormatInt(*p.ID, 10), Project: *p.PathWithNamespace, IID: *a.IID,
		HeadRef: *a.SourceBranch, HeadSHA: *a.LastCommit.ID, CloneURL: *p.GitHTTPURL,
		Author: Account{ID: *a.AuthorID}, Sender: sender,
	}
	switch {
	case *p.ID <= 0 || *a.TargetProjectID != *p.ID:
		return nil, "", errors.New("merge request is not of the hook's project")
	case ev.IID == 0:
		return nil, "", errors.New("merge request iid must be positive")
	case *a.AuthorID <= 0:
		return nil, "", errors.New("author id must be positive")
	}
	if ev.HeadProject, err = w.headProject(); err != nil {
		return nil, "", err
	}
	if ev.UpdatedAt, err = validate.GitLabTimestamp(*a.UpdatedAt); err != nil {
		return nil, "", fmt.Errorf("merge request updated_at: %w", err)
	}
	for _, check := range []error{
		validate.GitLabProjectPath(ev.Project), validate.GitRef(ev.HeadRef), validate.CommitSHA(ev.HeadSHA), validate.CloneURL(ev.CloneURL),
	} {
		if check != nil {
			return nil, "", check
		}
	}
	return ev, *a.Action, nil
}

// headProject is the path of the project the head lives in: the hook's own
// when the source is the target, the source's when it is a fork, "" when the
// fork was deleted. A fork the hook does not describe is an error.
func (w *mergeRequestHookWire) headProject() (string, error) {
	a := w.Attributes
	switch {
	case a.SourceProjectID == nil:
		return "", nil
	case *a.SourceProjectID == *a.TargetProjectID:
		return *w.Project.PathWithNamespace, nil
	case a.Source == nil || a.Source.PathWithNamespace == nil:
		return "", errors.New("fork head without its project")
	}
	if err := validate.GitLabProjectPath(*a.Source.PathWithNamespace); err != nil {
		return "", fmt.Errorf("head %w", err)
	}
	return *a.Source.PathWithNamespace, nil
}

// glAction maps GitLab's merge request action to previewd's.
func glAction(action string, oldRev *string) (string, error) {
	switch action {
	case "open":
		return ActionOpened, nil
	case "reopen":
		return ActionReopened, nil
	case "close", "merge":
		return ActionClosed, nil
	case "approved", "approval":
		return ActionApproved, nil
	case "unapproved", "unapproval":
		return ActionUnapproved, nil
	case "update":
		if oldRev != nil && *oldRev != "" {
			if err := validate.CommitSHA(*oldRev); err != nil {
				return "", fmt.Errorf("%w: oldrev: %w", validate.ErrPayload, err)
			}
			return ActionSynchronize, nil
		}
		return "", fmt.Errorf("%w: update without a new head", validate.ErrIgnoredAction)
	}
	return "", fmt.Errorf("%w: merge request action %s", validate.ErrIgnoredAction, validate.Quote(action))
}

// glIDs validates the identifiers every call is built from, before any call.
func glIDs(projectID, mrIID string) (iid uint32, base string, err error) {
	if err := validate.GitLabProjectID(projectID); err != nil {
		return 0, "", err
	}
	if iid, err = validate.MergeRequestIID(mrIID); err != nil {
		return 0, "", err
	}
	return iid, "/projects/" + projectID, nil
}

// request sends one GET authenticated by the token. The caller closes the
// body (decodeReply does).
func (g *GitLab) request(ctx context.Context, client *http.Client, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api+path, nil)
	if err != nil {
		return nil, fmt.Errorf("GET %s: build request: %w", path, err)
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	return resp, nil
}

// get performs one GET, requires HTTP 200 and decodes at most limit bytes of
// JSON into v. A larger reply is an error, never truncated.
func (g *GitLab) get(ctx context.Context, path string, limit int64, v any) error {
	resp, err := g.request(ctx, g.http, path)
	if err != nil {
		return err
	}
	return decodeReply(resp, http.MethodGet, path, http.StatusOK, limit, v)
}

// ResolveProject returns the numeric ID of the project at path
// (path_with_namespace, as a hook and PREVIEWD_APPROVERS name it), the handle
// every other call is addressed by. The path is validated and sent as one
// encoded segment, and the reply must name exactly that path: a project
// renamed or transferred since the hook is another project, not a match.
func (g *GitLab) ResolveProject(ctx context.Context, path string) (string, error) {
	if err := validate.GitLabProjectPath(path); err != nil {
		return "", fmt.Errorf("resolve project %s: %w", validate.Quote(path), err)
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var p struct {
		ID   *int64  `json:"id"`
		Path *string `json:"path_with_namespace"`
	}
	if err := g.get(ctx, "/projects/"+url.PathEscape(path), maxProjectReplyBytes, &p); err != nil {
		return "", fmt.Errorf("resolve project %s: %w", path, err)
	}
	if p.ID == nil || p.Path == nil || *p.ID < 1 || *p.Path != path {
		return "", fmt.Errorf("resolve project %s: the reply is not about that project", path)
	}
	return strconv.FormatInt(*p.ID, 10), nil
}

type glMergeRequestReply struct {
	IID             *uint32        `json:"iid"`
	State           *string        `json:"state"`
	SHA             *string        `json:"sha"`
	SourceProjectID *int64         `json:"source_project_id"`
	TargetProjectID *int64         `json:"target_project_id"`
	Author          *glAccountWire `json:"author"`
	Labels          []string       `json:"labels"`
}

// GetMRState implements Provider: projectID is the numeric project ID, mrIID
// the merge request's IID. The author's membership is read only for a head
// in the project itself, and its failure is an error, so a caller can tell
// "untrusted" from "could not tell".
func (g *GitLab) GetMRState(ctx context.Context, projectID, mrIID string) (*MRState, error) {
	iid, base, err := glIDs(projectID, mrIID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var mr glMergeRequestReply
	if err := g.get(ctx, base+"/merge_requests/"+mrIID, maxMRReplyBytes, &mr); err != nil {
		return nil, fmt.Errorf("read %s!%d: %w", projectID, iid, err)
	}
	st, err := g.state(mr, projectID, iid)
	if err != nil {
		return nil, fmt.Errorf("read %s!%d: %w", projectID, iid, err)
	}
	if mr.SourceProjectID != nil && *mr.SourceProjectID == *mr.TargetProjectID {
		st.HeadProject = projectID
		if st.Trusted, err = g.canPush(ctx, base, st.Author.ID); err != nil {
			return nil, fmt.Errorf("read %s!%d: %w", projectID, iid, err)
		}
	}
	return st, nil
}

// state validates a merge request reply into an untrusted state: the trust
// and the head project are decided by GetMRState.
func (g *GitLab) state(mr glMergeRequestReply, projectID string, iid uint32) (*MRState, error) {
	if mr.IID == nil || mr.State == nil || mr.SHA == nil || mr.TargetProjectID == nil {
		return nil, errors.New("the reply is incomplete")
	}
	if *mr.IID != iid || strconv.FormatInt(*mr.TargetProjectID, 10) != projectID {
		return nil, fmt.Errorf("the reply is for project %d, iid %d", *mr.TargetProjectID, *mr.IID)
	}
	st := &MRState{}
	switch *mr.State {
	case "opened":
		st.Open = true
	case "closed", "merged", "locked":
		// A locked request is being merged: nothing to deploy.
	default:
		return nil, fmt.Errorf("unknown merge request state %s", validate.Quote(*mr.State))
	}
	if err := validate.CommitSHA(*mr.SHA); err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	st.HeadSHA = *mr.SHA
	author, err := mr.Author.account("author")
	if err != nil {
		return nil, err
	}
	st.Author = author
	// Labels carry no authority on GitLab (approvals do): a name that is not
	// valid is left out, not an error.
	for _, l := range mr.Labels {
		if err := validate.LabelName(l); err != nil {
			g.logger.Debug("Ignoring a GitLab label", "label", validate.Quote(l))
			continue
		}
		st.Labels = append(st.Labels, l)
	}
	return st, nil
}

// canPush reports whether account id is an active member of the project,
// inherited memberships included, with Developer access or more. A user who
// is not a member is a plain false; any other failure is an error.
func (g *GitLab) canPush(ctx context.Context, base string, id int64) (bool, error) {
	path := base + "/members/all/" + strconv.FormatInt(id, 10)
	resp, err := g.request(ctx, g.http, path)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		g.logger.Debug("The merge request author is not a member of the project", "author_id", id)
		return false, nil
	}
	var m struct {
		ID          *int64  `json:"id"`
		State       *string `json:"state"`
		AccessLevel *int    `json:"access_level"`
	}
	if err := decodeReply(resp, http.MethodGet, path, http.StatusOK, maxReplyBytes, &m); err != nil {
		return false, err
	}
	if m.ID == nil || m.State == nil || m.AccessLevel == nil || *m.ID != id {
		return false, fmt.Errorf("membership reply is not about account %d: %w", id, ErrAccountMismatch)
	}
	return *m.State == "active" && *m.AccessLevel >= gitlabDeveloper, nil
}

// GetApprovals implements Provider. GitLab says who approves, not on which
// commit: Approval.CommitSHA is "".
func (g *GitLab) GetApprovals(ctx context.Context, projectID, mrIID string) ([]Approval, error) {
	iid, base, err := glIDs(projectID, mrIID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var reply struct {
		IID        *uint32 `json:"iid"`
		ProjectID  *int64  `json:"project_id"`
		ApprovedBy *[]struct {
			User *glAccountWire `json:"user"`
		} `json:"approved_by"`
	}
	if err := g.get(ctx, base+"/merge_requests/"+mrIID+"/approvals", maxReplyBytes, &reply); err != nil {
		return nil, fmt.Errorf("read the approvals of %s!%d: %w", projectID, iid, err)
	}
	if reply.IID == nil || reply.ProjectID == nil || reply.ApprovedBy == nil ||
		*reply.IID != iid || strconv.FormatInt(*reply.ProjectID, 10) != projectID {
		return nil, fmt.Errorf("read the approvals of %s!%d: the reply is incomplete or for another request", projectID, iid)
	}
	var out []Approval
	seen := map[int64]bool{}
	for _, a := range *reply.ApprovedBy {
		who, err := a.User.account("approver")
		if err != nil {
			return nil, fmt.Errorf("read the approvals of %s!%d: %w", projectID, iid, err)
		}
		if !seen[who.ID] {
			seen[who.ID] = true
			out = append(out, Approval{User: who})
		}
	}
	return out, nil
}
