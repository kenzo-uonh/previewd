package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// The GitLab gate is a deploy gate like the GHES one.
var _ Authorizer = (*GitLabAuthorizer)(nil)

const glRepo = "acme/sub/app"

// fakeMergeRequests is GitLab as the gate reads it: one project (15,
// acme/sub/app) with one merge request (7).
type fakeMergeRequests struct {
	state   vcs.MRState
	resolve error
	read    error
	calls   []string
}

func newFakeMergeRequests() *fakeMergeRequests {
	return &fakeMergeRequests{state: vcs.MRState{Open: true, HeadSHA: authCommit, HeadProject: "15",
		Author: vcs.Account{Login: "author", ID: 4242}, Trusted: true}}
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

func newGLGate(t *testing.T, f *fakeMergeRequests) *GitLabAuthorizer {
	t.Helper()
	a, err := NewGitLabAuthorizer(f, nil)
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

// Fails closed: nothing but a trusted, open merge request deploys. Approvals
// of untrusted ones are not supported yet.
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
		d, err := newGLGate(t, f).Authorize(context.Background(), glLease())
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
	if _, err := NewGitLabAuthorizer(nil, nil); err == nil {
		t.Error("no GitLab accepted")
	}
}
