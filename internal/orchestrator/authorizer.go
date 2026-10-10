package orchestrator

// The deploy gate (V1 spec D4, D-V1-5, V1-I3): before anything of a pull
// request is fetched, built or run, the authorizer classifies the leased
// deploy from what GHES says now, never from the webhook payload or the
// queue row.
//
//	trusted    the head lives in the base repository and its opener has
//	           admin, maintain or write permission there (vcs.Trusted)
//	untrusted  anything else: a fork, a deleted head repository, an opener
//	           without write access. It runs only on a live approval of its
//	           exact commit whose approver is still in PREVIEWD_APPROVERS
//	           (by account ID), whose review GHES still reports APPROVED on
//	           that commit (or, with the label opt-in, whose label is still
//	           on the PR and the commit still its head), and who still has
//	           write permission on the repository.
//
// Fail closed: a GHES read that fails is ErrUnavailable (the reconciler
// requeues the deploy unclassified and deploys nothing); anything that
// cannot be confirmed is ErrNotApproved (the reconciler parks it).
//
// Revalidate applies the same truth to a running environment (D-V1-5): a
// version built trusted needs its PR to be trusted now; one built on an
// approval needs that approval confirmed again (or the PR trusted now).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// Authorization errors. ErrNotApproved is the store's: Classify returns the
// same error when a live approval disappears before the deploy is recorded.
var (
	ErrUnavailable = errors.New("GHES unavailable: the deploy is not classified")
	ErrNotApproved = store.ErrNotApproved
)

// Review states as GHES names them.
const (
	reviewApproved         = "APPROVED"
	reviewChangesRequested = "CHANGES_REQUESTED"
	reviewDismissed        = "DISMISSED"
)

// GitHub is the GHES truth the authorizer reads (vcs.Client). Each call
// mints and revokes its own repository-scoped token.
type GitHub interface {
	PullRequest(ctx context.Context, repo string, number uint32) (vcs.PRState, error)
	Reviews(ctx context.Context, repo string, number uint32) ([]vcs.ReviewState, error)
	Permission(ctx context.Context, repo string, who vcs.Account) (string, error)
}

// Approvals is the store's record of approvals (store.Store).
type Approvals interface {
	LiveApproval(ctx context.Context, envID, commitSHA string) (store.Approval, bool, error)
}

// Decision is the classification of one leased deploy. Its fields are
// store.Classification's: Classify records it as confirmed.
type Decision struct {
	Trust    store.Trust     // TrustTrusted or TrustUntrusted
	Approval *store.Approval // the approval it runs on; nil for a trusted deploy
	// FullSecrets: D-V1-1 opt-in (PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS),
	// an approved untrusted deploy that receives the trusted section.
	FullSecrets bool
}

// RevokedError is a refusal: the deploy or the running environment is not
// authorized. It wraps ErrNotApproved. Reason is the revocation the
// Revalidator records with its teardown, "" when there is no approval to
// revoke (none live, or a trusted version whose PR is no longer trusted).
type RevokedError struct {
	Reason store.RevocationReason
	Err    error
}

func (e *RevokedError) Error() string { return e.Err.Error() }
func (e *RevokedError) Unwrap() error { return e.Err }

// refuse returns a RevokedError wrapping ErrNotApproved.
func refuse(reason store.RevocationReason, format string, args ...any) error {
	return &RevokedError{Reason: reason, Err: fmt.Errorf(format+": %w", append(args, ErrNotApproved)...)}
}

// AuthorizerConfig wires the GHES authorizer. GitHub and Approvals are
// required; Approvers is config.Config.Approvers (owner/repo -> accounts).
type AuthorizerConfig struct {
	GitHub        GitHub
	Approvals     Approvals
	Approvers     map[string][]validate.Approver
	LabelApproval bool   // PREVIEWD_LABEL_APPROVAL
	ApprovalLabel string // PREVIEWD_APPROVAL_LABEL, required with LabelApproval
	// FullSecretsRepos: PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS (D-V1-1).
	FullSecretsRepos map[string]bool
	Logger           *slog.Logger
}

// GHESAuthorizer classifies deploys from GHES.
type GHESAuthorizer struct {
	cfg AuthorizerConfig
}

// NewAuthorizer validates cfg.
func NewAuthorizer(cfg AuthorizerConfig) (*GHESAuthorizer, error) {
	switch {
	case cfg.GitHub == nil:
		return nil, errors.New("authorizer: no GHES client")
	case cfg.Approvals == nil:
		return nil, errors.New("authorizer: no approval store")
	case cfg.LabelApproval && cfg.ApprovalLabel == "":
		return nil, errors.New("authorizer: label approval without an approval label")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &GHESAuthorizer{cfg: cfg}, nil
}

// Authorize classifies the leased deploy l from GHES. It returns a trusted
// or an untrusted Decision, or an error wrapping ErrUnavailable (requeue,
// unclassified) or ErrNotApproved (park). Any other error is the store's or
// a lease that is not a deploy: nothing is deployed either way.
func (a *GHESAuthorizer) Authorize(ctx context.Context, l store.Lease) (Decision, error) {
	if l.Type != store.JobDeploy {
		return Decision{}, fmt.Errorf("authorize job %d: a %s is never authorized", l.JobID, l.Type)
	}
	src := l.Source
	number, pr, err := a.pullRequest(ctx, src)
	if err != nil {
		return Decision{}, fmt.Errorf("authorize job %d: %w", l.JobID, err)
	}
	if vcs.Trusted(pr, src.Repo) {
		return Decision{Trust: store.TrustTrusted}, nil
	}
	approval, err := a.approved(ctx, l.EnvID, src, pr, number)
	if err != nil {
		return Decision{}, fmt.Errorf("authorize job %d of %s#%d at %s (untrusted: %s): %w", l.JobID, src.Repo, src.PRNumber, src.CommitSHA, untrusted(pr), err)
	}
	return Decision{Trust: store.TrustUntrusted, Approval: &approval, FullSecrets: a.cfg.FullSecretsRepos[src.Repo]}, nil
}

// Revalidate re-checks the running version built by j, a SUCCESS deploy
// (store.Running), against GHES now (D-V1-5, V1-I4):
//   - built trusted, or before V1 (unclassified, the full secret set): its
//     PR must still be trusted, whatever approval exists;
//   - built on an approval: its PR trusted now, or its approval confirmed
//     again exactly as Authorize confirms it.
//
// nil: still authorized. A *RevokedError (ErrNotApproved): tear it down.
// ErrUnavailable: GHES did not answer; the Revalidator's grace applies.
func (a *GHESAuthorizer) Revalidate(ctx context.Context, j store.Job) error {
	if j.Type != store.JobDeploy || j.Status != store.StatusSuccess {
		return fmt.Errorf("revalidate job %d: a %s %s builds nothing that runs", j.ID, j.Status, j.Type)
	}
	src := j.Source
	number, pr, err := a.pullRequest(ctx, src)
	if err != nil {
		return fmt.Errorf("revalidate %s: %w", j.EnvID, err)
	}
	trustedNow := vcs.Trusted(pr, src.Repo)
	switch {
	case trustedNow:
		return nil
	case j.Trust != store.TrustUntrusted:
		return fmt.Errorf("revalidate %s, built %s at %s: %w", j.EnvID, j.Trust, src.CommitSHA,
			refuse("", "the pull request is no longer trusted (%s)", untrusted(pr)))
	}
	if _, err := a.approved(ctx, j.EnvID, src, pr, number); err != nil {
		return fmt.Errorf("revalidate %s, built on an approval of %s (untrusted: %s): %w", j.EnvID, src.CommitSHA, untrusted(pr), err)
	}
	return nil
}

// pullRequest reads src's pull request from GHES and returns its number
// as GHES takes it; a read failure wraps ErrUnavailable.
func (a *GHESAuthorizer) pullRequest(ctx context.Context, src store.Source) (uint32, vcs.PRState, error) {
	if src.PRNumber < 1 || src.PRNumber > math.MaxUint32 {
		return 0, vcs.PRState{}, fmt.Errorf("pull request number %d out of range", src.PRNumber)
	}
	number := uint32(src.PRNumber)
	pr, err := a.cfg.GitHub.PullRequest(ctx, src.Repo, number)
	if err != nil {
		return 0, vcs.PRState{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return number, pr, nil
}

// untrusted says why a pull request is not trusted, for errors and logs.
func untrusted(pr vcs.PRState) string {
	return fmt.Sprintf("head repository %q, opener %s#%d with %q", pr.HeadRepo, pr.Opener.Login, pr.Opener.ID, pr.OpenerPermission)
}

// approved confirms against GHES the newest live approval of src's commit
// in envID: the one Classify will audit. A refusal is a *RevokedError whose
// reason the Revalidator records.
func (a *GHESAuthorizer) approved(ctx context.Context, envID string, src store.Source, pr vcs.PRState, number uint32) (store.Approval, error) {
	g, live, err := a.cfg.Approvals.LiveApproval(ctx, envID, src.CommitSHA)
	switch {
	case err != nil:
		return store.Approval{}, err
	case !live:
		return store.Approval{}, refuse("", "no live approval of the commit")
	}
	configured, ok := a.approver(src.Repo, g.ApproverID)
	if !ok {
		return store.Approval{}, refuse(store.RevokedApproverRemoved, "approver %s#%d is not in PREVIEWD_APPROVERS for %s", g.ApproverLogin, g.ApproverID, src.Repo)
	}
	who := vcs.Account{Login: g.ApproverLogin, ID: g.ApproverID}
	switch g.Via {
	case store.ApprovalViaReview:
		reviews, err := a.cfg.GitHub.Reviews(ctx, src.Repo, number)
		if err != nil {
			return store.Approval{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		rv, ok := latestVerdict(reviews, g.ApproverID)
		switch {
		case !ok:
			return store.Approval{}, refuse(store.RevokedDismissed, "approver %s#%d has no review on GHES", g.ApproverLogin, g.ApproverID)
		case rv.State == reviewChangesRequested:
			return store.Approval{}, refuse(store.RevokedChangesRequested, "approver %s#%d's latest review %d requests changes", rv.User.Login, rv.User.ID, rv.ID)
		case rv.State != reviewApproved:
			return store.Approval{}, refuse(store.RevokedDismissed, "approver %s#%d's latest review %d is %s", rv.User.Login, rv.User.ID, rv.ID, rv.State)
		case rv.CommitID != src.CommitSHA:
			return store.Approval{}, refuse(store.RevokedDismissed, "approver %s#%d's latest review %d approves %s, not this commit", rv.User.Login, rv.User.ID, rv.ID, rv.CommitID)
		}
		who = rv.User // the login GHES reports now: a renamed approver keeps the ID
	case store.ApprovalViaLabel:
		switch {
		case !a.cfg.LabelApproval:
			return store.Approval{}, refuse("", "label approval is off (PREVIEWD_LABEL_APPROVAL)")
		case !slices.Contains(pr.Labels, a.cfg.ApprovalLabel):
			return store.Approval{}, refuse(store.RevokedUnlabeled, "the approval label %q is no longer on the pull request", a.cfg.ApprovalLabel)
		case pr.HeadSHA != src.CommitSHA:
			// A label carries no commit: it approves the head it was set on
			// (D-V1-3). The push's delivery records the new-head revocation.
			return store.Approval{}, refuse("", "the head moved to %s since the label", pr.HeadSHA)
		}
	default:
		return store.Approval{}, refuse("", "approval via %q", g.Via)
	}
	if who.Login != configured.Login {
		a.cfg.Logger.Warn("Approver login differs from PREVIEWD_APPROVERS (renamed account?): matched on the account ID",
			"repository", src.Repo, "approver_id", who.ID, "login", who.Login, "configured_login", configured.Login)
	}
	perm, err := a.cfg.GitHub.Permission(ctx, src.Repo, who)
	switch {
	case errors.Is(err, vcs.ErrAccountMismatch):
		return store.Approval{}, refuse(store.RevokedPermissionLost, "approver %s#%d cannot be identified on GHES (%v)", who.Login, who.ID, err)
	case err != nil:
		return store.Approval{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	case !vcs.WriteAccess(perm):
		return store.Approval{}, refuse(store.RevokedPermissionLost, "approver %s#%d has %q permission, not write", who.Login, who.ID, perm)
	}
	return g, nil
}

// approver returns the PREVIEWD_APPROVERS entry of repo for account id: the
// account ID is the identity, never the login.
func (a *GHESAuthorizer) approver(repo string, id int64) (validate.Approver, bool) {
	for _, ap := range a.cfg.Approvers[repo] {
		if ap.ID == id {
			return ap, true
		}
	}
	return validate.Approver{}, false
}

// latestVerdict returns account id's latest approval, change request or
// dismissed review, in GHES's chronological order. Comments and pending
// reviews decide nothing. A dismissed review is a verdict: an approval
// dismissed (or an approval followed by a dismissed change request) needs
// a fresh approval.
func latestVerdict(reviews []vcs.ReviewState, id int64) (vcs.ReviewState, bool) {
	var last vcs.ReviewState
	found := false
	for _, rv := range reviews {
		if rv.User.ID != id {
			continue
		}
		switch rv.State {
		case reviewApproved, reviewChangesRequested, reviewDismissed:
			last, found = rv, true
		}
	}
	return last, found
}
