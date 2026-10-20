package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// The GitLab gate is a deploy gate like the GHES one.
var _ Authorizer = (*GitLabAuthorizer)(nil)

const glRepo = "acme/sub/app"

// fakeMergeRequests is GitLab as the gate reads it: one project (15,
// acme/sub/app) with one merge request (7).
type fakeMergeRequests struct {
	state     vcs.MRState
	approvals []vcs.Approval
	push      map[int64]bool // account -> may push
	resolve   error
	read      error
	failing   map[string]error // call -> error
	calls     []string
}

func newFakeMergeRequests() *fakeMergeRequests {
	return &fakeMergeRequests{
		state:     vcs.MRState{Open: true, HeadSHA: authCommit, HeadProject: "15", Author: vcs.Account{Login: "author", ID: 4242}, Trusted: true},
		approvals: []vcs.Approval{{User: vcs.Account{Login: "lead.dev", ID: approverID}}},
		push:      map[int64]bool{approverID: true},
		failing:   map[string]error{},
	}
}

func (f *fakeMergeRequests) GetApprovals(_ context.Context, projectID, iid string) ([]vcs.Approval, error) {
	f.calls = append(f.calls, "approvals:"+projectID+"!"+iid)
	if err := f.failing["approvals"]; err != nil {
		return nil, err
	}
	return f.approvals, nil
}

func (f *fakeMergeRequests) CanPush(_ context.Context, projectID string, id int64) (bool, error) {
	f.calls = append(f.calls, fmt.Sprintf("push:%s#%d", projectID, id))
	if err := f.failing["push"]; err != nil {
		return false, err
	}
	return f.push[id], nil
}

func (f *fakeMergeRequests) ResolveProject(_ context.Context, path string) (string, error) {
	f.calls = append(f.calls, "resolve:"+path)
	if f.resolve != nil {
		return "", f.resolve
	}
	if path != glRepo {
		return "", fmt.Errorf("unexpected project %s", path)
	}
	return "15", nil
}

func (f *fakeMergeRequests) GetMRState(_ context.Context, projectID, iid string) (*vcs.MRState, error) {
	f.calls = append(f.calls, "state:"+projectID+"!"+iid)
	if f.read != nil {
		return nil, f.read
	}
	if projectID != "15" || iid != "7" {
		return nil, fmt.Errorf("unexpected read of %s!%s", projectID, iid)
	}
	st := f.state
	return &st, nil
}

func glLease() store.Lease {
	return store.Lease{JobID: 1, EnvID: "pr-7-abc", Type: store.JobDeploy,
		Source: store.Source{Repo: glRepo, HeadRepo: glRepo, PRNumber: 7, OpenerLogin: "gitlab-user-4242", OpenerID: 4242, CommitSHA: authCommit}}
}

// fakeGrants is the store's record of approvals.
type fakeGrants struct {
	grant store.Approval
	live  bool
	err   error
}

func (f *fakeGrants) LiveApproval(_ context.Context, envID, commit string) (store.Approval, bool, error) {
	if f.err != nil {
		return store.Approval{}, false, f.err
	}
	if envID != "pr-7-abc" || commit != authCommit {
		return store.Approval{}, false, fmt.Errorf("unexpected read of %s at %s", envID, commit)
	}
	return f.grant, f.live, nil
}

func liveGrant() *fakeGrants {
	return &fakeGrants{live: true, grant: store.Approval{EnvID: "pr-7-abc", CommitSHA: authCommit,
		ApproverLogin: "lead.dev", ApproverID: approverID, Via: store.ApprovalViaMR}}
}

func newGLGate(t *testing.T, f *fakeMergeRequests) *GitLabAuthorizer {
	t.Helper()
	return newGLGateWith(t, f, liveGrant())
}

func newGLGateWith(t *testing.T, f *fakeMergeRequests, g Approvals) *GitLabAuthorizer {
	t.Helper()
	a, err := NewGitLabAuthorizer(GitLabAuthorizerConfig{
		MergeRequests: f, Approvals: g,
		Approvers:        map[string][]validate.Approver{glRepo: {{Login: "lead.dev", ID: approverID}}},
		FullSecretsRepos: map[string]bool{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestGitLabAuthorizeTrustsAMemberAuthoredMergeRequestOfTheProject(t *testing.T) {
	f := newFakeMergeRequests()
	d, err := newGLGate(t, f).Authorize(context.Background(), glLease())
	if err != nil {
		t.Fatal(err)
	}
	if d.Trust != store.TrustTrusted || d.Approval != nil || d.FullSecrets {
		t.Errorf("decision = %+v, want trusted with no approval", d)
	}
	if got := fmt.Sprint(f.calls); got != "[resolve:acme/sub/app state:15!7]" {
		t.Errorf("calls %s", got)
	}
}

// Fails closed: an untrusted or closed merge request with no live approval
// of its commit deploys nothing.
func TestGitLabAuthorizeRefusesWhatIsNotTrusted(t *testing.T) {
	for name, edit := range map[string]func(*vcs.MRState){
		"untrusted author": func(s *vcs.MRState) { s.Trusted = false },
		"fork":             func(s *vcs.MRState) { s.Trusted, s.HeadProject = false, "88" },
		"deleted fork":     func(s *vcs.MRState) { s.Trusted, s.HeadProject = false, "" },
		"closed":           func(s *vcs.MRState) { s.Open = false },
		// Trusted alone is not enough if the head is not in the base project.
		"trusted flag with a foreign head": func(s *vcs.MRState) { s.HeadProject = "88" },
	} {
		f := newFakeMergeRequests()
		edit(&f.state)
		d, err := newGLGateWith(t, f, &fakeGrants{}).Authorize(context.Background(), glLease())
		var revoked *RevokedError
		if !errors.Is(err, ErrNotApproved) || !errors.As(err, &revoked) || d.Trust != "" || d.Approval != nil {
			t.Errorf("%s: decision %+v, err %v; want ErrNotApproved and nothing", name, d, err)
		}
	}
}

func TestGitLabAuthorizeIsUnavailableWhenGitLabCannotBeRead(t *testing.T) {
	boom := errors.New("connection refused")
	for name, edit := range map[string]func(*fakeMergeRequests){
		"project": func(f *fakeMergeRequests) { f.resolve = boom },
		"state":   func(f *fakeMergeRequests) { f.read = boom },
	} {
		f := newFakeMergeRequests()
		edit(f)
		d, err := newGLGate(t, f).Authorize(context.Background(), glLease())
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotApproved) || d.Trust != "" {
			t.Errorf("%s: decision %+v, err %v; want ErrUnavailable and nothing", name, d, err)
		}
	}
}

func TestGitLabAuthorizeRefusesWhatIsNotADeployOrNotInRange(t *testing.T) {
	f := newFakeMergeRequests()
	g := newGLGate(t, f)
	teardown := glLease()
	teardown.Type = store.JobTeardown
	if _, err := g.Authorize(context.Background(), teardown); err == nil {
		t.Error("a teardown was authorized")
	}
	for _, n := range []int64{0, -1, 1 << 32} {
		l := glLease()
		l.Source.PRNumber = n
		if d, err := g.Authorize(context.Background(), l); err == nil || d.Trust != "" {
			t.Errorf("merge request %d: %+v, %v; want an error", n, d, err)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("GitLab was read for a lease that cannot be a merge request: %v", f.calls)
	}
}

func glRunning() store.Job {
	return store.Job{ID: 1, EnvID: "pr-7-abc", Type: store.JobDeploy, Status: store.StatusSuccess, Trust: store.TrustTrusted, Source: glLease().Source}
}

func TestGitLabRevalidate(t *testing.T) {
	f := newFakeMergeRequests()
	g := newGLGate(t, f)
	if err := g.Revalidate(context.Background(), glRunning()); err != nil {
		t.Fatalf("a trusted running version was refused: %v", err)
	}

	f.state.Trusted = false // the author lost Developer access
	err := g.Revalidate(context.Background(), glRunning())
	var revoked *RevokedError
	if !errors.Is(err, ErrNotApproved) || !errors.As(err, &revoked) {
		t.Fatalf("an author without write access kept the environment: %v", err)
	}

	f.state.Trusted, f.state.Open = true, false
	if err := g.Revalidate(context.Background(), glRunning()); !errors.Is(err, ErrNotApproved) {
		t.Errorf("a closed merge request kept the environment: %v", err)
	}

	f.state.Open = true
	f.read = errors.New("connection refused")
	if err := g.Revalidate(context.Background(), glRunning()); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotApproved) {
		t.Errorf("unreadable GitLab: %v; want ErrUnavailable (the grace period decides)", err)
	}

	pending := glRunning()
	pending.Status = store.StatusPendingApproval
	if err := g.Revalidate(context.Background(), pending); err == nil || errors.Is(err, ErrNotApproved) {
		t.Errorf("a job that built nothing was revalidated: %v", err)
	}
}

func TestNewGitLabAuthorizerNeedsGitLab(t *testing.T) {
	if _, err := NewGitLabAuthorizer(GitLabAuthorizerConfig{Approvals: &fakeGrants{}}); err == nil {
		t.Error("no GitLab accepted")
	}
	if _, err := NewGitLabAuthorizer(GitLabAuthorizerConfig{MergeRequests: newFakeMergeRequests()}); err == nil {
		t.Error("no approval store accepted")
	}
}

// An untrusted merge request (here a fork) runs on a live approval of its
// exact commit whose approver is still in PREVIEWD_APPROVERS, still approves
// on GitLab, and can still push.
func forkOf(f *fakeMergeRequests) *fakeMergeRequests {
	f.state.Trusted, f.state.HeadProject = false, "88"
	return f
}

func TestGitLabAuthorizeRunsAnUntrustedMergeRequestOnItsApproval(t *testing.T) {
	f := forkOf(newFakeMergeRequests())
	grants := liveGrant()
	g := newGLGateWith(t, f, grants)
	d, err := g.Authorize(context.Background(), glLease())
	if err != nil {
		t.Fatal(err)
	}
	if d.Trust != store.TrustUntrusted || d.Approval == nil || *d.Approval != grants.grant || d.FullSecrets {
		t.Errorf("decision = %+v", d)
	}
	if got := fmt.Sprint(f.calls); got != "[resolve:acme/sub/app state:15!7 approvals:15!7 push:15#7]" {
		t.Errorf("calls %s", got)
	}

	// The opt-in of the repository rides the verdict.
	g.cfg.FullSecretsRepos = map[string]bool{glRepo: true}
	if d, err = g.Authorize(context.Background(), glLease()); err != nil || !d.FullSecrets {
		t.Errorf("full secrets opt-in: %+v, %v", d, err)
	}
}

func TestGitLabAuthorizeRefusesAnApprovalGitLabNoLongerBacks(t *testing.T) {
	for name, tc := range map[string]struct {
		edit   func(*fakeMergeRequests, *fakeGrants, *GitLabAuthorizer)
		reason store.RevocationReason
	}{
		"no live approval": {edit: func(_ *fakeMergeRequests, g *fakeGrants, _ *GitLabAuthorizer) { g.live = false }},
		"approver left PREVIEWD_APPROVERS": {reason: store.RevokedApproverRemoved,
			edit: func(_ *fakeMergeRequests, _ *fakeGrants, a *GitLabAuthorizer) {
				a.cfg.Approvers = map[string][]validate.Approver{glRepo: {{Login: "other", ID: 99}}}
			}},
		"approver of another repository": {reason: store.RevokedApproverRemoved,
			edit: func(_ *fakeMergeRequests, _ *fakeGrants, a *GitLabAuthorizer) {
				a.cfg.Approvers = map[string][]validate.Approver{"acme/other": {{Login: "lead.dev", ID: approverID}}}
			}},
		"approval by a review": {edit: func(_ *fakeMergeRequests, g *fakeGrants, _ *GitLabAuthorizer) { g.grant.Via = store.ApprovalViaReview }},
		"approval by a label":  {edit: func(_ *fakeMergeRequests, g *fakeGrants, _ *GitLabAuthorizer) { g.grant.Via = store.ApprovalViaLabel }},
		"head moved":           {edit: func(f *fakeMergeRequests, _ *fakeGrants, _ *GitLabAuthorizer) { f.state.HeadSHA = otherCommit }},
		"approval withdrawn": {reason: store.RevokedDismissed,
			edit: func(f *fakeMergeRequests, _ *fakeGrants, _ *GitLabAuthorizer) { f.approvals = nil }},
		"only another account approves": {reason: store.RevokedDismissed,
			edit: func(f *fakeMergeRequests, _ *fakeGrants, _ *GitLabAuthorizer) {
				f.approvals = []vcs.Approval{{User: vcs.Account{Login: "lead.dev", ID: 8}}}
			}},
		"approver cannot push any more": {reason: store.RevokedPermissionLost,
			edit: func(f *fakeMergeRequests, _ *fakeGrants, _ *GitLabAuthorizer) { f.push[approverID] = false }},
		"closed": {edit: func(f *fakeMergeRequests, _ *fakeGrants, _ *GitLabAuthorizer) { f.state.Open = false }},
		// Never a second pair of eyes: the approval of the author counts for nothing.
		"approver is the author": {edit: func(f *fakeMergeRequests, _ *fakeGrants, _ *GitLabAuthorizer) { f.state.Author.ID = approverID }},
	} {
		f := forkOf(newFakeMergeRequests())
		grants := liveGrant()
		g := newGLGateWith(t, f, grants)
		tc.edit(f, grants, g)
		d, err := g.Authorize(context.Background(), glLease())
		var revoked *RevokedError
		if !errors.Is(err, ErrNotApproved) || !errors.As(err, &revoked) || revoked.Reason != tc.reason || d.Trust != "" || d.Approval != nil {
			t.Errorf("%s: decision %+v, err %v (reason %q); want ErrNotApproved with reason %q", name, d, err, reasonOf(revoked), tc.reason)
		}
	}
}

func TestGitLabAuthorizeIsUnavailableWhenAnApprovalCannotBeConfirmed(t *testing.T) {
	boom := errors.New("connection refused")
	for _, call := range []string{"approvals", "push"} {
		f := forkOf(newFakeMergeRequests())
		f.failing[call] = boom
		d, err := newGLGate(t, f).Authorize(context.Background(), glLease())
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotApproved) || d.Trust != "" {
			t.Errorf("%s: decision %+v, err %v; want ErrUnavailable", call, d, err)
		}
	}
	// A store that cannot answer deploys nothing and parks nothing.
	f := forkOf(newFakeMergeRequests())
	d, err := newGLGateWith(t, f, &fakeGrants{err: errors.New("database is locked")}).Authorize(context.Background(), glLease())
	if err == nil || errors.Is(err, ErrNotApproved) || errors.Is(err, ErrUnavailable) || d.Trust != "" {
		t.Errorf("store failure: %+v, %v", d, err)
	}
}

func TestGitLabRevalidateConfirmsTheApprovalARunningVersionWasBuiltOn(t *testing.T) {
	built := func() store.Job { j := glRunning(); j.Trust = store.TrustUntrusted; return j }
	f := forkOf(newFakeMergeRequests())
	g := newGLGate(t, f)
	if err := g.Revalidate(context.Background(), built()); err != nil {
		t.Fatalf("an approved version was refused: %v", err)
	}

	f.approvals = nil // withdrawn
	err := g.Revalidate(context.Background(), built())
	var revoked *RevokedError
	if !errors.Is(err, ErrNotApproved) || !errors.As(err, &revoked) || revoked.Reason != store.RevokedDismissed {
		t.Errorf("a withdrawn approval kept the environment: %v", err)
	}

	f.approvals = []vcs.Approval{{User: vcs.Account{Login: "lead.dev", ID: approverID}}}
	f.failing["approvals"] = errors.New("connection refused")
	if err := g.Revalidate(context.Background(), built()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("unreadable approvals: %v; want ErrUnavailable", err)
	}

	// Trusted now: the approval no longer matters.
	f = newFakeMergeRequests()
	if err := newGLGateWith(t, f, &fakeGrants{}).Revalidate(context.Background(), built()); err != nil {
		t.Errorf("a version whose merge request is trusted now was refused: %v", err)
	}
}

func reasonOf(e *RevokedError) store.RevocationReason {
	if e == nil {
		return ""
	}
	return e.Reason
}
