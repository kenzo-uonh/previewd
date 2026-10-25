package vcs

// The developer feedback loop (V1.1 spec 3.3): a commit status that follows
// the deploy (pending, then success or failure) and one sticky comment on
// the pull or merge request with the live preview URL. The comment is found
// again by its marker and updated in place, so a request carries one of them
// however many commits it sees.
//
// Feedback is a courtesy to the developer, never a dependency of the
// deploy: the reconciler logs a failure here and goes on. What it writes is
// built only from validated identifiers and previewd's own vocabulary, never
// from the request's title, branch or description.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// CommentMarker identifies previewd's sticky comment. It is the first line
// of the comment; the driver finds the comment by it, among the comments its
// own credential wrote.
const CommentMarker = "<!-- previewd-status -->"

// Commit status states, as previewd names them whatever the forge calls
// them (GitLab's failure is "failed").
const (
	StatePending = "pending"
	StateSuccess = "success"
	StateFailure = "failure"
)

const (
	// statusContext names previewd's status among a commit's checks.
	statusContext = "previewd"
	// maxDescription is GitHub's limit on a status description.
	maxDescription = 140
	// maxCommentBytes bounds a comment body: ours is under a kilobyte.
	maxCommentBytes = 16 << 10
	maxPreviewURL   = 2048
	maxLoginBytes   = 255
	maxStepBytes    = 32
)

// Status is where a deploy stands, for the developer. Every field is
// validated where it is rendered.
type Status struct {
	Repo      string // as the store keeps it: owner/repo, or a GitLab project path
	PRNumber  int64
	CommitSHA string
	URL       string // the preview URL
	// Approver and ApproverID say who authorized an untrusted deploy; both
	// are zero for a trusted one.
	Approver   string
	ApproverID int64
	Expires    time.Time // zero: the preview does not expire
	// Failure is the step a failed deploy stopped at (store.Failure's closed
	// vocabulary); empty for a deploy that succeeded or is under way.
	Failure string
}

// Comment renders the sticky comment of s: green when it carries no
// failure, red with the step when it does.
func (s Status) Comment() (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	if s.Failure == "" {
		b.WriteString("### 🟢 Preview ready\n\n")
	} else {
		fmt.Fprintf(&b, "### 🔴 Preview failed at `%s`\n\n", s.Failure)
	}
	b.WriteString("| | |\n|---|---|\n")
	if s.Failure == "" {
		fmt.Fprintf(&b, "| **URL** | [%s](%s) |\n", s.URL, s.URL)
	}
	fmt.Fprintf(&b, "| **Commit** | `%s` |\n", s.CommitSHA[:12])
	if s.Approver == "" {
		b.WriteString("| **Authorized** | trusted: the author can push to the project |\n")
	} else {
		fmt.Fprintf(&b, "| **Authorized** | approved by `%s#%d` |\n", s.Approver, s.ApproverID)
	}
	if s.Failure == "" {
		if s.Expires.IsZero() {
			b.WriteString("| **Expires** | never |\n")
		} else {
			fmt.Fprintf(&b, "| **Expires** | %s |\n", s.Expires.UTC().Format("2006-01-02 15:04 UTC"))
		}
	}
	return b.String(), nil
}

// description is the status description of state, at most maxDescription bytes.
func (s Status) description(state string) string {
	switch state {
	case StatePending:
		return "Deploying the preview"
	case StateSuccess:
		return "Preview ready"
	}
	return "Preview failed at " + s.Failure
}

func (s Status) check() error {
	switch {
	case s.PRNumber < 1:
		return fmt.Errorf("feedback: request number %d", s.PRNumber)
	case validate.CommitSHA(s.CommitSHA) != nil:
		return fmt.Errorf("feedback: commit %s", validate.Quote(s.CommitSHA))
	case s.Failure == "" && checkPreviewURL(s.URL) != nil, s.Failure != "" && s.URL != "" && checkPreviewURL(s.URL) != nil:
		return fmt.Errorf("feedback: preview URL %s", validate.Quote(s.URL))
	case (s.Approver == "") != (s.ApproverID == 0), s.ApproverID < 0:
		return fmt.Errorf("feedback: approver %s#%d", validate.Quote(s.Approver), s.ApproverID)
	case s.Approver != "" && !plainName(s.Approver, maxLoginBytes):
		return fmt.Errorf("feedback: approver %s", validate.Quote(s.Approver))
	case s.Failure != "" && !plainStep(s.Failure):
		return fmt.Errorf("feedback: failure step %s", validate.Quote(s.Failure))
	}
	return nil
}

// plainName accepts what a login or a username is made of, and nothing a
// markdown renderer could act on.
func plainName(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func plainStep(s string) bool {
	if s == "" || len(s) > maxStepBytes {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

// checkPreviewURL accepts only the URL of a preview: http or https, a DNS
// host with an optional port, no user info, no path, query or fragment.
func checkPreviewURL(s string) error {
	if s == "" || len(s) > maxPreviewURL {
		return errors.New("empty or too long")
	}
	for i := range len(s) {
		if c := s[i]; c <= ' ' || c > '~' || strings.IndexByte("<>\"'`()[]\\", c) >= 0 {
			return errors.New("invalid character")
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("not an http(s) URL")
	case u.User != nil, u.RawQuery != "", u.Fragment != "", u.Opaque != "", u.Path != "" && u.Path != "/":
		return errors.New("not the bare URL of a preview")
	}
	return validate.DNSName(u.Hostname())
}

// checkStatus validates the arguments of SetCommitStatus before any call.
func checkStatus(commitSHA, state, targetURL, description string) error {
	if err := validate.CommitSHA(commitSHA); err != nil {
		return fmt.Errorf("commit status: %w", err)
	}
	switch state {
	case StatePending, StateSuccess, StateFailure:
	default:
		return fmt.Errorf("commit status: state %s is not pending, success or failure", validate.Quote(state))
	}
	if targetURL != "" {
		if err := checkPreviewURL(targetURL); err != nil {
			return fmt.Errorf("commit status: target URL %s: %w", validate.Quote(targetURL), err)
		}
	}
	if description == "" || len(description) > maxDescription || !utf8.ValidString(description) || strings.ContainsFunc(description, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return fmt.Errorf("commit status: description of %d bytes", len(description))
	}
	return nil
}

// checkComment validates the arguments of PostComment before any call: the
// body must carry the marker, once, as its first line.
func checkComment(body string) error {
	switch {
	case !strings.HasPrefix(body, CommentMarker+"\n"), strings.Count(body, CommentMarker) != 1:
		return errors.New("comment: the body does not start with the previewd marker, once")
	case len(body) > maxCommentBytes, !utf8.ValidString(body):
		return fmt.Errorf("comment: body of %d bytes", len(body))
	}
	return nil
}

// Notifier gives a deploy's progress to the forge through a Provider. The
// project a request lives in is addressed by resolve: the store keeps a
// GitLab project by its path, the API wants its ID. A nil resolve addresses
// the project by Repo, as GitHub does.
type Notifier struct {
	p       Provider
	resolve func(ctx context.Context, repo string) (string, error)
}

// NewNotifier returns a Notifier writing through p.
func NewNotifier(p Provider, resolve func(ctx context.Context, repo string) (string, error)) *Notifier {
	return &Notifier{p: p, resolve: resolve}
}

func (n *Notifier) project(ctx context.Context, repo string) (string, error) {
	if n.resolve == nil {
		return repo, nil
	}
	id, err := n.resolve(ctx, repo)
	if err != nil {
		return "", fmt.Errorf("feedback for %s: %w", repo, err)
	}
	return id, nil
}

// Begin sets the pending status of s's commit.
func (n *Notifier) Begin(ctx context.Context, s Status) error {
	id, err := n.project(ctx, s.Repo)
	if err != nil {
		return err
	}
	return n.p.SetCommitStatus(ctx, id, s.CommitSHA, StatePending, "", s.description(StatePending))
}

// Succeed sets the success status, carrying the preview URL, and posts or
// updates the sticky comment. Both are attempted; a failure of either is
// returned.
func (n *Notifier) Succeed(ctx context.Context, s Status) error {
	s.Failure = ""
	return n.finish(ctx, s, StateSuccess, s.URL)
}

// Fail sets the failure status naming s.Failure and updates the sticky
// comment. Both are attempted; a failure of either is returned.
func (n *Notifier) Fail(ctx context.Context, s Status) error {
	if s.Failure == "" {
		return errors.New("feedback: a failure names the step it stopped at")
	}
	return n.finish(ctx, s, StateFailure, "")
}

func (n *Notifier) finish(ctx context.Context, s Status, state, targetURL string) error {
	body, err := s.Comment()
	if err != nil {
		return err
	}
	id, err := n.project(ctx, s.Repo)
	if err != nil {
		return err
	}
	statusErr := n.p.SetCommitStatus(ctx, id, s.CommitSHA, state, targetURL, s.description(state))
	commentErr := n.p.PostComment(ctx, id, strconv.FormatInt(s.PRNumber, 10), body)
	return errors.Join(statusErr, commentErr)
}
