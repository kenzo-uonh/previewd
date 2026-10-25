package orchestrator

// The deploy gate of a GitLab deployment (V1.1 spec 3.1): the counterpart of
// GHESAuthorizer for merge requests, reading GitLab now, never the hook or
// the queue row.
//
//	trusted    the merge request is open, its head lives in the project and
//	           its author is an active member with Developer access or more
//	           (vcs.GitLab.GetMRState)
//	untrusted  anything else: a fork, a deleted head project, an author who
//	           cannot push. It runs only on a live approval of its exact
//	           commit (store: the head its approval hook named) whose
//	           approver is still in PREVIEWD_APPROVERS (by account ID), still
//	           approves the merge request on GitLab, and can still push. The
//	           head must still be that commit: a GitLab approval names no
//	           commit and survives a push, so the commit is the store's.
//	closed     refused, whatever approves it.
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
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// MergeRequests is the GitLab truth the gate reads (vcs.GitLab). The store
// keeps a project by its path; GitLab is addressed by the numeric ID.
type MergeRequests interface {
	ResolveProject(ctx context.Context, path string) (string, error)
	GetMRState(ctx context.Context, projectID, mrIID string) (*vcs.MRState, error)
	GetApprovals(ctx context.Context, projectID, mrIID string) ([]vcs.Approval, error)
	CanPush(ctx context.Context, projectID string, id int64) (bool, error)
}

// GitLabAuthorizerConfig wires the GitLab gate. MergeRequests and Approvals
// are required; Approvers is config.Config.Approvers (project path ->
// accounts).
type GitLabAuthorizerConfig struct {
	MergeRequests MergeRequests
	Approvals     Approvals
	Approvers     map[string][]validate.Approver
	// FullSecretsRepos: PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS (D-V1-1).
	FullSecretsRepos map[string]bool
	Logger           *slog.Logger
}

// GitLabAuthorizer classifies deploys from GitLab.
type GitLabAuthorizer struct {
	cfg GitLabAuthorizerConfig
}

// NewGitLabAuthorizer validates cfg; a nil logger is slog.Default.
func NewGitLabAuthorizer(cfg GitLabAuthorizerConfig) (*GitLabAuthorizer, error) {
	switch {
	case cfg.MergeRequests == nil:
		return nil, errors.New("authorizer: no GitLab client")
	case cfg.Approvals == nil:
		return nil, errors.New("authorizer: no approval store")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &GitLabAuthorizer{cfg: cfg}, nil
}

// Authorize classifies the leased deploy l: a trusted or an untrusted
// Decision, or an error wrapping ErrUnavailable (requeue, unclassified) or
// ErrNotApproved (park). Any other error is the store's or a lease that is
// not a deploy: nothing is deployed either way.
func (a *GitLabAuthorizer) Authorize(ctx context.Context, l store.Lease) (Decision, error) {
	if l.Type != store.JobDeploy {
		return Decision{}, fmt.Errorf("authorize job %d: a %s is never authorized", l.JobID, l.Type)
	}
	src := l.Source
	mr, err := a.read(ctx, src)
	if err != nil {
		return Decision{}, fmt.Errorf("authorize job %d: %w", l.JobID, err)
	}
	if err := mr.open(); err != nil {
		return Decision{}, fmt.Errorf("authorize job %d of %s!%d at %s: %w", l.JobID, src.Repo, src.PRNumber, src.CommitSHA, err)
	}
	if mr.trusted() {
		return Decision{Trust: store.TrustTrusted}, nil
	}
	approval, err := a.approved(ctx, l.EnvID, src, mr)
	if err != nil {
		return Decision{}, fmt.Errorf("authorize job %d of %s!%d at %s (untrusted: %s): %w", l.JobID, src.Repo, src.PRNumber, src.CommitSHA, mr.why(), err)
	}
	return Decision{Trust: store.TrustUntrusted, Approval: &approval, FullSecrets: a.cfg.FullSecretsRepos[src.Repo]}, nil
}

// Revalidate re-checks the running version built by j, a SUCCESS deploy,
// against GitLab now (D-V1-5, V1-I4): its merge request must be open and
// trusted, or, for a version built on an approval, that approval confirmed
// again exactly as Authorize confirms it. nil: still authorized. A
// *RevokedError (ErrNotApproved): tear it down. ErrUnavailable: GitLab did
// not answer; the Revalidator's grace applies.
func (a *GitLabAuthorizer) Revalidate(ctx context.Context, j store.Job) error {
	if j.Type != store.JobDeploy || j.Status != store.StatusSuccess {
		return fmt.Errorf("revalidate job %d: a %s %s builds nothing that runs", j.ID, j.Status, j.Type)
	}
	src := j.Source
	mr, err := a.read(ctx, src)
	if err != nil {
		return fmt.Errorf("revalidate %s: %w", j.EnvID, err)
	}
	if err := mr.open(); err != nil {
		return fmt.Errorf("revalidate %s, built %s at %s: %w", j.EnvID, j.Trust, src.CommitSHA, err)
	}
	switch {
	case mr.trusted():
		return nil
	case j.Trust != store.TrustUntrusted:
		return fmt.Errorf("revalidate %s, built %s at %s: %w", j.EnvID, j.Trust, src.CommitSHA,
			refuse("", "the merge request is no longer trusted (%s)", mr.why()))
	}
	if _, err := a.approved(ctx, j.EnvID, src, mr); err != nil {
		return fmt.Errorf("revalidate %s, built on an approval of %s (untrusted: %s): %w", j.EnvID, src.CommitSHA, mr.why(), err)
	}
	return nil
}

// request is a merge request as GitLab reports it now.
type request struct {
	project string // the numeric project ID
	iid     string
	state   *vcs.MRState
}

func (r request) open() error {
	if !r.state.Open {
		return refuse("", "the merge request is not open")
	}
	return nil
}

// trusted: the head lives in the project and the author can push. The flag
// is the driver's; the head project is checked again here.
func (r request) trusted() bool { return r.state.Trusted && r.state.HeadProject == r.project }

func (r request) why() string {
	return fmt.Sprintf("head project %q, author %s#%d", r.state.HeadProject, r.state.Author.Login, r.state.Author.ID)
}

// read resolves src's project and reads its merge request; any failure wraps
// ErrUnavailable.
func (a *GitLabAuthorizer) read(ctx context.Context, src store.Source) (request, error) {
	if src.PRNumber < 1 || src.PRNumber > math.MaxUint32 {
		return request{}, fmt.Errorf("merge request number %d out of range", src.PRNumber)
	}
	project, err := a.cfg.MergeRequests.ResolveProject(ctx, src.Repo)
	if err != nil {
		return request{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	iid := strconv.FormatInt(src.PRNumber, 10)
	st, err := a.cfg.MergeRequests.GetMRState(ctx, project, iid)
	if err != nil {
		return request{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return request{project: project, iid: iid, state: st}, nil
}

// approved confirms against GitLab the newest live approval of src's commit
// in envID: the one Classify will audit. A refusal is a *RevokedError whose
// reason the Revalidator records.
func (a *GitLabAuthorizer) approved(ctx context.Context, envID string, src store.Source, mr request) (store.Approval, error) {
	g, live, err := a.cfg.Approvals.LiveApproval(ctx, envID, src.CommitSHA)
	switch {
	case err != nil:
		return store.Approval{}, err
	case !live:
		return store.Approval{}, refuse("", "no live approval of the commit")
	case g.Via != store.ApprovalViaMR:
		return store.Approval{}, refuse("", "approval via %q is not a GitLab approval", g.Via)
	case !a.isApprover(src.Repo, g.ApproverID):
		return store.Approval{}, refuse(store.RevokedApproverRemoved, "approver %s#%d is not in PREVIEWD_APPROVERS for %s", g.ApproverLogin, g.ApproverID, src.Repo)
	case g.ApproverID == mr.state.Author.ID:
		return store.Approval{}, refuse("", "approver %s#%d is the author: an approval is a second pair of eyes", g.ApproverLogin, g.ApproverID)
	case mr.state.HeadSHA != src.CommitSHA:
		// An approval names no commit: it approves the head its hook named.
		// The push's delivery records the new-head revocation.
		return store.Approval{}, refuse("", "the head moved to %s since the approval", mr.state.HeadSHA)
	}
	approvals, err := a.cfg.MergeRequests.GetApprovals(ctx, mr.project, mr.iid)
	if err != nil {
		return store.Approval{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(vcs.Authorized(approvals, []validate.Approver{{Login: g.ApproverLogin, ID: g.ApproverID}})) == 0 {
		return store.Approval{}, refuse(store.RevokedDismissed, "approver %s#%d no longer approves the merge request on GitLab", g.ApproverLogin, g.ApproverID)
	}
	canPush, err := a.cfg.MergeRequests.CanPush(ctx, mr.project, g.ApproverID)
	switch {
	case errors.Is(err, vcs.ErrAccountMismatch):
		return store.Approval{}, refuse(store.RevokedPermissionLost, "approver %s#%d cannot be identified on GitLab (%v)", g.ApproverLogin, g.ApproverID, err)
	case err != nil:
		return store.Approval{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	case !canPush:
		return store.Approval{}, refuse(store.RevokedPermissionLost, "approver %s#%d is not an active member with Developer access or more", g.ApproverLogin, g.ApproverID)
	}
	return g, nil
}

// isApprover reports whether account id is listed for repo: the account ID is
// the identity, never the login.
func (a *GitLabAuthorizer) isApprover(repo string, id int64) bool {
	for _, ap := range a.cfg.Approvers[repo] {
		if ap.ID == id {
			return true
		}
	}
	return false
}
