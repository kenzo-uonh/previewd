package validate

import (
	"encoding/json"
	"fmt"
	"time"
)

// pull_request_review actions and review states previewd acts on.
const (
	ActionSubmitted = "submitted"
	ActionDismissed = "dismissed"

	ReviewApproved         = "approved"
	ReviewChangesRequested = "changes_requested"
)

// Review is a validated pull_request_review event: every field has passed
// its validator. PullRequest carries the pull request as the event saw it
// (its Action is the review's). CommitSHA is the reviewed commit, which an
// approval is bound to (V1-I3); HeadSHA in PullRequest is the head when
// the review was sent.
type Review struct {
	PullRequest
	State         string // approved, changes_requested, dismissed, ...
	ReviewID      int64
	ReviewerLogin string
	ReviewerID    int64
	CommitSHA     string
	SubmittedAt   time.Time // zero for a dismissal without it
}

type reviewWire struct {
	Action *string `json:"action"`
	Review *struct {
		ID          *int64       `json:"id"`
		User        *accountWire `json:"user"`
		CommitID    *string      `json:"commit_id"`
		State       *string      `json:"state"`
		SubmittedAt *string      `json:"submitted_at"`
	} `json:"review"`
	PullRequest *pullRequestObjectWire `json:"pull_request"`
	Repository  *repositoryWire        `json:"repository"`
	Sender      *accountWire           `json:"sender"`
}

// ParseReview decodes and validates a pull_request_review webhook body.
// The review's ID, author, commit and state, and the pull request fields
// ParsePullRequest requires, are required for every action; submitted_at
// is required for a submitted review. A well-formed event that previewd
// does not act on (an edit, a comment review) returns ErrIgnoredAction.
func ParseReview(body []byte) (Review, error) {
	reject := func(format string, args ...any) (Review, error) {
		return Review{}, fmt.Errorf("%w: %s", ErrPayload, fmt.Sprintf(format, args...))
	}

	if len(body) > MaxPayloadBytes {
		return reject("body exceeds %d bytes", MaxPayloadBytes)
	}
	var w reviewWire
	if err := json.Unmarshal(body, &w); err != nil {
		return reject("invalid JSON: %v", err)
	}
	if w.Action == nil || w.Review == nil || w.Review.ID == nil || w.Review.User == nil ||
		w.Review.User.Login == nil || w.Review.User.ID == nil || w.Review.CommitID == nil ||
		w.Review.State == nil || w.PullRequest == nil {
		return reject("missing required field")
	}
	rv := Review{
		PullRequest:   PullRequest{Action: *w.Action},
		State:         *w.Review.State,
		ReviewID:      *w.Review.ID,
		ReviewerLogin: *w.Review.User.Login,
		ReviewerID:    *w.Review.User.ID,
		CommitSHA:     *w.Review.CommitID,
	}
	if err := pullRequestFields(w.PullRequest.Number, w.PullRequest, w.Repository, w.Sender, &rv.PullRequest); err != nil {
		return reject("%v", err)
	}
	if rv.ReviewID <= 0 {
		return reject("review id must be positive")
	}
	if err := account("reviewer", rv.ReviewerLogin, rv.ReviewerID); err != nil {
		return reject("%v", err)
	}
	if err := CommitSHA(rv.CommitSHA); err != nil {
		return reject("review %v", err)
	}
	if err := reviewState(rv.State); err != nil {
		return reject("%v", err)
	}
	if w.Review.SubmittedAt != nil {
		t, err := Timestamp(*w.Review.SubmittedAt)
		if err != nil {
			return reject("review submitted_at: %v", err)
		}
		rv.SubmittedAt = t
	}

	switch {
	case rv.Action == ActionSubmitted && rv.SubmittedAt.IsZero():
		return reject("missing required field")
	case rv.Action == ActionSubmitted && (rv.State == ReviewApproved || rv.State == ReviewChangesRequested),
		rv.Action == ActionDismissed:
		return rv, nil
	default:
		return rv, ErrIgnoredAction
	}
}

// reviewState accepts a lower-case review state of at most 32 bytes:
// GitHub's set (approved, changes_requested, commented, dismissed,
// pending) may grow, and an unknown state is ignored, never acted on.
func reviewState(s string) error {
	if s == "" || len(s) > 32 {
		return fmt.Errorf("invalid review state %s", quote(s))
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && c != '_' {
			return fmt.Errorf("invalid review state %s", quote(s))
		}
	}
	return nil
}
