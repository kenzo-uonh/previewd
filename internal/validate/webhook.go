package validate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// SignatureHeader carries "sha256=<hex HMAC-SHA256 of the raw body>".
	SignatureHeader = "X-Hub-Signature-256"
	// MaxPayloadBytes bounds a webhook body. Larger bodies are rejected,
	// never truncated (truncation would change what the HMAC covers).
	MaxPayloadBytes = 1 << 20

	signaturePrefix = "sha256="
	maxCloneURLLen  = 2048
)

// Pull request actions previewd acts on.
const (
	ActionOpened      = "opened"
	ActionReopened    = "reopened"
	ActionSynchronize = "synchronize"
	ActionClosed      = "closed"
	ActionLabeled     = "labeled"
	ActionUnlabeled   = "unlabeled"
)

var (
	// ErrSignature rejects a body whose signature is missing, malformed or
	// wrong, or that arrives while no secret is configured.
	ErrSignature = errors.New("webhook signature rejected")
	// ErrPayload rejects a body that is too large or breaks the schema.
	ErrPayload = errors.New("webhook payload rejected")
	// ErrIgnoredAction marks a well-formed event previewd does not act on.
	ErrIgnoredAction = errors.New("pull request action ignored")
)

// VerifySignature accepts body only if header is exactly
// "sha256=" + 64 lowercase hex digits of HMAC-SHA256(secret, body). An empty
// secret rejects everything: there is no unauthenticated mode.
func VerifySignature(secret, body []byte, header string) error {
	if len(secret) == 0 {
		return fmt.Errorf("%w: no webhook secret configured", ErrSignature)
	}
	if len(body) > MaxPayloadBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrSignature, MaxPayloadBytes)
	}
	digest, ok := strings.CutPrefix(header, signaturePrefix)
	if !ok || len(digest) != hex.EncodedLen(sha256.Size) || strings.ToLower(digest) != digest {
		return fmt.Errorf("%w: malformed signature header", ErrSignature)
	}
	got, err := hex.DecodeString(digest)
	if err != nil {
		return fmt.Errorf("%w: malformed signature header", ErrSignature)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return fmt.Errorf("%w: signature mismatch", ErrSignature)
	}
	return nil
}

// PullRequest is a validated pull_request event: every field has passed its
// validator. HeadRepo and the opener are recorded with the job; trust is
// never decided from them, but from GHES at AuthorizeDeploy (D-V1-5).
// UpdatedAt is the signed time the delivery GUID is bound to (V1-I7).
type PullRequest struct {
	Action      string
	Number      uint32
	Repo        string
	HeadRef     string
	HeadSHA     string
	CloneURL    string
	HeadRepo    string // "" when the head repository (a fork) was deleted
	OpenerLogin string
	OpenerID    int64
	UpdatedAt   time.Time
	SenderLogin string
	SenderID    int64
	Label       string // labeled and unlabeled only
}

// accountWire is a GitHub account object.
type accountWire struct {
	Login *string `json:"login"`
	ID    *int64  `json:"id"`
}

// pullRequestObjectWire is the pull_request object of pull_request and
// pull_request_review events.
type pullRequestObjectWire struct {
	Number *uint32 `json:"number"`
	Head   *struct {
		Ref  *string `json:"ref"`
		SHA  *string `json:"sha"`
		Repo *struct {
			FullName *string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	User      *accountWire `json:"user"`
	UpdatedAt *string      `json:"updated_at"`
}

type repositoryWire struct {
	FullName *string `json:"full_name"`
	CloneURL *string `json:"clone_url"`
}

type pullRequestWire struct {
	Action      *string                `json:"action"`
	Number      *uint32                `json:"number"`
	PullRequest *pullRequestObjectWire `json:"pull_request"`
	Repository  *repositoryWire        `json:"repository"`
	Sender      *accountWire           `json:"sender"`
	Label       *struct {
		Name *string `json:"name"`
	} `json:"label"`
}

// pullRequestFields decodes what both event kinds carry about the pull
// request into pr, validated. number is the event's PR number.
func pullRequestFields(number *uint32, o *pullRequestObjectWire, repo *repositoryWire, sender *accountWire, pr *PullRequest) error {
	if number == nil || o == nil || o.Head == nil || o.Head.Ref == nil || o.Head.SHA == nil ||
		o.User == nil || o.User.Login == nil || o.User.ID == nil || o.UpdatedAt == nil ||
		(o.Head.Repo != nil && o.Head.Repo.FullName == nil) ||
		repo == nil || repo.FullName == nil || repo.CloneURL == nil ||
		sender == nil || sender.Login == nil || sender.ID == nil {
		return errors.New("missing required field")
	}
	pr.Number, pr.Repo, pr.CloneURL = *number, *repo.FullName, *repo.CloneURL
	pr.HeadRef, pr.HeadSHA = *o.Head.Ref, *o.Head.SHA
	pr.OpenerLogin, pr.OpenerID = *o.User.Login, *o.User.ID
	pr.SenderLogin, pr.SenderID = *sender.Login, *sender.ID
	if o.Head.Repo != nil {
		pr.HeadRepo = *o.Head.Repo.FullName
		if err := RepoFullName(pr.HeadRepo); err != nil {
			return fmt.Errorf("head %w", err)
		}
	}
	if pr.Number == 0 {
		return errors.New("pull request number must be positive")
	}
	if err := account("opener", pr.OpenerLogin, pr.OpenerID); err != nil {
		return err
	}
	if err := account("sender", pr.SenderLogin, pr.SenderID); err != nil {
		return err
	}
	updated, err := Timestamp(*o.UpdatedAt)
	if err != nil {
		return fmt.Errorf("pull request updated_at: %w", err)
	}
	pr.UpdatedAt = updated
	if err := RepoFullName(pr.Repo); err != nil {
		return err
	}
	if err := GitRef(pr.HeadRef); err != nil {
		return err
	}
	if err := CommitSHA(pr.HeadSHA); err != nil {
		return err
	}
	return cloneURL(pr.CloneURL)
}

// account validates a login and its numeric account ID.
func account(role, login string, id int64) error {
	if err := Login(login); err != nil {
		return fmt.Errorf("%s %w", role, err)
	}
	if id <= 0 {
		return fmt.Errorf("%s id must be positive", role)
	}
	return nil
}

// ParsePullRequest decodes and validates a pull_request webhook body. The
// fields previewd uses are required for every action, so a `closed` event
// derives the same environment ID as the `opened` one. head.repo may be
// null (a deleted fork) and is then "". labeled and unlabeled carry the
// label's name. A well-formed event with another action returns
// ErrIgnoredAction.
func ParsePullRequest(body []byte) (PullRequest, error) {
	reject := func(format string, args ...any) (PullRequest, error) {
		return PullRequest{}, fmt.Errorf("%w: %s", ErrPayload, fmt.Sprintf(format, args...))
	}

	if len(body) > MaxPayloadBytes {
		return reject("body exceeds %d bytes", MaxPayloadBytes)
	}
	var w pullRequestWire
	if err := json.Unmarshal(body, &w); err != nil {
		return reject("invalid JSON: %v", err)
	}
	if w.Action == nil {
		return reject("missing required field")
	}
	pr := PullRequest{Action: *w.Action}
	if err := pullRequestFields(w.Number, w.PullRequest, w.Repository, w.Sender, &pr); err != nil {
		return reject("%v", err)
	}

	switch pr.Action {
	case ActionOpened, ActionReopened, ActionSynchronize, ActionClosed:
		return pr, nil
	case ActionLabeled, ActionUnlabeled:
		if w.Label == nil || w.Label.Name == nil {
			return reject("missing required field")
		}
		if err := LabelName(*w.Label.Name); err != nil {
			return reject("%v", err)
		}
		pr.Label = *w.Label.Name
		return pr, nil
	default:
		return pr, ErrIgnoredAction
	}
}

// cloneURL checks syntax only. Which schemes and hosts may be fetched is the
// fetch policy's decision (internal/vcs).
func cloneURL(s string) error {
	if s == "" || len(s) > maxCloneURLLen {
		return fmt.Errorf("invalid clone url length %d", len(s))
	}
	for i := range len(s) {
		if c := s[i]; c <= 0x20 || c == 0x7f {
			return fmt.Errorf("clone url contains a control or space character")
		}
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.User != nil {
		return fmt.Errorf("clone url must be absolute and carry no credentials")
	}
	return nil
}
