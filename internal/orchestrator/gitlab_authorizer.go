package orchestrator

// The deploy gate of a GitLab deployment (V1.1 spec 3.1): the counterpart of
// GHESAuthorizer for merge requests, reading GitLab now, never the hook or
// the queue row.
//
//	trusted    the merge request is open, its head lives in the project and
//	           its author is an active member with Developer access or more
//	           (vcs.GitLab.GetMRState)
//	untrusted  anything else: a fork, a deleted head project, an author who
//	           cannot push, a closed request. Refused (ErrNotApproved): GitLab
//	           approvals are not recorded yet, so nothing approves it.
//
// Fail closed, as the GHES gate: a read that fails is ErrUnavailable (the
// reconciler requeues the deploy unclassified and deploys nothing); anything
// not confirmed is ErrNotApproved.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// MergeRequests is the GitLab truth the gate reads (vcs.GitLab). The store
// keeps a project by its path; GitLab is addressed by the numeric ID.
type MergeRequests interface {
	ResolveProject(ctx context.Context, path string) (string, error)
	GetMRState(ctx context.Context, projectID, mrIID string) (*vcs.MRState, error)
}

// GitLabAuthorizer classifies deploys from GitLab.
type GitLabAuthorizer struct {
	mr     MergeRequests
	logger *slog.Logger
}

// NewGitLabAuthorizer returns the gate reading mr; a nil logger is
// slog.Default.
func NewGitLabAuthorizer(mr MergeRequests, logger *slog.Logger) (*GitLabAuthorizer, error) {
	if mr == nil {
		return nil, errors.New("authorizer: no GitLab client")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &GitLabAuthorizer{mr: mr, logger: logger}, nil
}

// Authorize classifies the leased deploy l: a trusted Decision, or an error
// wrapping ErrUnavailable (requeue, unclassified) or ErrNotApproved (park).
func (a *GitLabAuthorizer) Authorize(ctx context.Context, l store.Lease) (Decision, error) {
	if l.Type != store.JobDeploy {
		return Decision{}, fmt.Errorf("authorize job %d: a %s is never authorized", l.JobID, l.Type)
	}
	why, err := a.verdict(ctx, l.Source)
	switch {
	case errors.Is(err, ErrUnavailable):
		return Decision{}, fmt.Errorf("authorize job %d: %w", l.JobID, err)
	case err != nil:
		return Decision{}, fmt.Errorf("authorize job %d of %s!%d at %s: %w", l.JobID, l.Source.Repo, l.Source.PRNumber, l.Source.CommitSHA, err)
	case why != "":
		return Decision{}, fmt.Errorf("authorize job %d of %s!%d at %s: %w", l.JobID, l.Source.Repo, l.Source.PRNumber, l.Source.CommitSHA, refuse("", "%s", why))
	}
	return Decision{Trust: store.TrustTrusted}, nil
}

// Revalidate re-checks the running version built by j, a SUCCESS deploy,
// against GitLab now: its merge request must still be trusted. nil: still
// authorized. A *RevokedError (ErrNotApproved): tear it down.
// ErrUnavailable: GitLab did not answer; the Revalidator's grace applies.
func (a *GitLabAuthorizer) Revalidate(ctx context.Context, j store.Job) error {
	if j.Type != store.JobDeploy || j.Status != store.StatusSuccess {
		return fmt.Errorf("revalidate job %d: a %s %s builds nothing that runs", j.ID, j.Status, j.Type)
	}
	why, err := a.verdict(ctx, j.Source)
	switch {
	case err != nil:
		return fmt.Errorf("revalidate %s: %w", j.EnvID, err)
	case why != "":
		return fmt.Errorf("revalidate %s, built %s at %s: %w", j.EnvID, j.Trust, j.Source.CommitSHA, refuse("", "%s", why))
	}
	return nil
}

// verdict reads the merge request of src and says why it is not trusted ("" when
// it is). The error wraps ErrUnavailable when GitLab could not be read.
func (a *GitLabAuthorizer) verdict(ctx context.Context, src store.Source) (string, error) {
	if src.PRNumber < 1 || src.PRNumber > math.MaxUint32 {
		return "", fmt.Errorf("merge request number %d out of range", src.PRNumber)
	}
	project, err := a.mr.ResolveProject(ctx, src.Repo)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	st, err := a.mr.GetMRState(ctx, project, strconv.FormatInt(src.PRNumber, 10))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch {
	case !st.Open:
		return "the merge request is not open", nil
	case !st.Trusted || st.HeadProject != project:
		return fmt.Sprintf("untrusted: head project %q, author %s#%d (GitLab approvals are not supported yet)", st.HeadProject, st.Author.Login, st.Author.ID), nil
	}
	return "", nil
}
