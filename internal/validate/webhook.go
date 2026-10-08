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
}

type pullRequestWire struct {
	Action      *string `json:"action"`
	Number      *uint32 `json:"number"`
	PullRequest *struct {
		Head *struct {
			Ref  *string `json:"ref"`
			SHA  *string `json:"sha"`
			Repo *struct {
				FullName *string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
		User *struct {
			Login *string `json:"login"`
			ID    *int64  `json:"id"`
		} `json:"user"`
	} `json:"pull_request"`
	Repository *struct {
		FullName *string `json:"full_name"`
		CloneURL *string `json:"clone_url"`
	} `json:"repository"`
}

// ParsePullRequest decodes and validates a pull_request webhook body. The
// fields previewd uses are required for every action, so a `closed` event
// derives the same environment ID as the `opened` one. head.repo may be
// null (a deleted fork) and is then "". A well-formed event with another
// action returns ErrIgnoredAction.
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
	if w.Action == nil || w.Number == nil || w.PullRequest == nil || w.PullRequest.Head == nil ||
		w.PullRequest.Head.Ref == nil || w.PullRequest.Head.SHA == nil ||
		w.PullRequest.User == nil || w.PullRequest.User.Login == nil || w.PullRequest.User.ID == nil ||
		(w.PullRequest.Head.Repo != nil && w.PullRequest.Head.Repo.FullName == nil) ||
		w.Repository == nil || w.Repository.FullName == nil || w.Repository.CloneURL == nil {
		return reject("missing required field")
	}

	pr := PullRequest{
		Action:   *w.Action,
		Number:   *w.Number,
		Repo:     *w.Repository.FullName,
		HeadRef:  *w.PullRequest.Head.Ref,
		HeadSHA:  *w.PullRequest.Head.SHA,
		CloneURL: *w.Repository.CloneURL,

		OpenerLogin: *w.PullRequest.User.Login,
		OpenerID:    *w.PullRequest.User.ID,
	}
	if w.PullRequest.Head.Repo != nil {
		pr.HeadRepo = *w.PullRequest.Head.Repo.FullName
		if err := RepoFullName(pr.HeadRepo); err != nil {
			return reject("head %v", err)
		}
	}
	if pr.Number == 0 {
		return reject("pull request number must be positive")
	}
	if err := Login(pr.OpenerLogin); err != nil {
		return reject("opener %v", err)
	}
	if pr.OpenerID <= 0 {
		return reject("opener id must be positive")
	}
	if err := RepoFullName(pr.Repo); err != nil {
		return reject("%v", err)
	}
	if err := GitRef(pr.HeadRef); err != nil {
		return reject("%v", err)
	}
	if err := CommitSHA(pr.HeadSHA); err != nil {
		return reject("%v", err)
	}
	if err := cloneURL(pr.CloneURL); err != nil {
		return reject("%v", err)
	}

	switch pr.Action {
	case ActionOpened, ActionReopened, ActionSynchronize, ActionClosed:
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
