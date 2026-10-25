package vcs

// The forge abstraction (V1.1 spec 3.1). previewd reads a pull or merge
// request from a forge in four ways: it authenticates a webhook, decodes it,
// fetches the source of a commit, and asks the forge for the truth (the
// request's state, who approves it) in the step that records an approval.
// Each forge is a Provider; the daemon runs exactly one
// (PREVIEWD_VCS_PROVIDER). Nothing here holds a secret: the webhook secret
// is a parameter, and a driver keeps its API credential to itself.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// Provider names.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
)

// Event actions, as previewd names them whatever the forge calls them. A
// GitLab "open", "update" (a push), "close", "merge" and "approval" are
// ActionOpened, ActionSynchronize, ActionClosed, ActionClosed and
// ActionApproved.
const (
	ActionOpened      = validate.ActionOpened
	ActionReopened    = validate.ActionReopened
	ActionSynchronize = validate.ActionSynchronize
	ActionClosed      = validate.ActionClosed
	ActionLabeled     = validate.ActionLabeled
	ActionUnlabeled   = validate.ActionUnlabeled
	ActionApproved    = "approved"
	ActionUnapproved  = "unapproved"
)

// Provider is a forge previewd serves.
//
// A project is addressed by ProjectID: owner/repo on GitHub, the numeric
// project ID on GitLab (a path is never put in a GitLab URL). A request is
// addressed by its number within the project, mrIID, in canonical decimal.
type Provider interface {
	// Name is ProviderGitHub or ProviderGitLab.
	Name() string
	// VerifyWebhook authenticates req against secret and returns its body,
	// read up to validate.MaxPayloadBytes. An empty secret, a missing or
	// wrong proof and a body above the cap are all errors: no delivery is
	// ever accepted unauthenticated. The body is only returned once verified.
	VerifyWebhook(req *http.Request, secret []byte) ([]byte, error)
	// ParseEvent decodes and validates a verified body. A well-formed event
	// previewd does not act on returns validate.ErrIgnoredAction, a malformed
	// one validate.ErrPayload; neither returns an event.
	ParseEvent(payload []byte) (*Event, error)
	// FetchTarball extracts the tree of commitSHA into destDir, which it
	// creates, under the bounds of extractTarball. maxBytes caps both the
	// compressed archive and what it extracts.
	FetchTarball(ctx context.Context, projectID, commitSHA, destDir string, maxBytes int64) error
	// GetMRState reads the request as the forge reports it now.
	GetMRState(ctx context.Context, projectID, mrIID string) (*MRState, error)
	// GetApprovals reads who approves the request now.
	GetApprovals(ctx context.Context, projectID, mrIID string) ([]Approval, error)
	// SetCommitStatus sets previewd's status (StatePending, StateSuccess or
	// StateFailure) on the commit. targetURL is "" or the preview URL.
	SetCommitStatus(ctx context.Context, projectID, commitSHA, state, targetURL, description string) error
	// PostComment keeps previewd's one sticky comment on the request: body
	// starts with CommentMarker, and the comment this driver's credential
	// already wrote with that marker is updated in place, else one is
	// created. It never touches a comment another account wrote.
	PostComment(ctx context.Context, projectID, mrIID, body string) error
}

// Event is a validated webhook: every field has passed its validator.
type Event struct {
	Action    string // one of the Action constants
	ProjectID string // the handle the API is addressed by
	Project   string // the project's path, for logs and PREVIEWD_APPROVERS
	IID       uint32
	HeadRef   string
	HeadSHA   string
	// HeadProject is the project the head lives in, "" once it was deleted.
	// It differs from Project for a fork.
	HeadProject string
	CloneURL    string
	// Author opened the request. A GitLab webhook names its author by ID
	// only: Login is then "", and GetMRState has the name.
	Author Account
	// Sender caused the event: the pusher, the approver, who closed it.
	Sender Account
	// UpdatedAt is the request's update time, signed with the body.
	UpdatedAt time.Time
	Label     string // ActionLabeled and ActionUnlabeled only
}

// MRState is a request as the forge reports it at the time of the call: the
// truth an approval or a revocation is judged against.
type MRState struct {
	Open    bool
	HeadSHA string
	// HeadProject is "" once the head project was deleted.
	HeadProject string
	Author      Account
	// Trusted is the trust rule: the head lives in the base project and its
	// author can write there. A fork, a deleted head or an author who cannot
	// write is never trusted.
	Trusted bool
	Labels  []string
}

// Approval is one account's standing approval of a request.
type Approval struct {
	User Account
	// CommitSHA is the commit the approval was given on, "" when the forge
	// does not say (GitLab does not bind an approval to a commit unless the
	// project resets approvals on push). The caller binds an approval to the
	// exact head with the commit its webhook recorded, never by assuming.
	CommitSHA string
}

// Authorized returns the approvals given by an account listed in approvers.
// The account ID is the identity: a login that matches while the ID does not
// is another account, and a renamed account keeps its approval.
func Authorized(approvals []Approval, approvers []validate.Approver) []Approval {
	var out []Approval
	for _, a := range approvals {
		for _, who := range approvers {
			if who.ID == a.User.ID {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// ErrBodyTooLarge rejects a webhook body above validate.MaxPayloadBytes. It
// is an ErrPayload.
var ErrBodyTooLarge = fmt.Errorf("%w: body too large", validate.ErrPayload)

// readWebhookBody reads req's body up to validate.MaxPayloadBytes. A larger
// body is an error, never truncated: truncation would change what a
// signature covers.
func readWebhookBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, fmt.Errorf("%w: no body", validate.ErrPayload)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, validate.MaxPayloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read webhook body: %w", err)
	}
	if len(body) > validate.MaxPayloadBytes {
		return nil, fmt.Errorf("%w: above %d bytes", ErrBodyTooLarge, validate.MaxPayloadBytes)
	}
	return body, nil
}

// restoreBody lets a handler read the verified body again.
func restoreBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
}

// errNoSecret rejects every delivery while no secret is configured.
var errNoSecret = errors.New("no webhook secret configured")
