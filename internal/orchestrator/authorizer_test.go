package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// The commit the rig's deliveries deploy.
const (
	authCommit  = "0123456789abcdef0123456789abcdef01234567"
	otherCommit = "89abcdef0123456789abcdef0123456789abcdef"
	approverID  = 7
)

// fakeGitHub is GHES as the authorizer reads it. accounts maps a login to
// the account that holds it now; perms an account ID to its permission.
type fakeGitHub struct {
	mu       sync.Mutex
	pr       vcs.PRState
	reviews  []vcs.ReviewState
	accounts map[string]int64
	perms    map[int64]string
	fail     map[string]error // call -> error
	calls    []string
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{
		pr: vcs.PRState{Open: true, HeadSHA: authCommit, HeadRepo: "acme/app",
			Opener: vcs.Account{Login: "opener", ID: 4242}, OpenerPermission: "write"},
		accounts: map[string]int64{"lead-dev": approverID},
		perms:    map[int64]string{approverID: "write"},
		fail:     map[string]error{},
	}
}

func (f *fakeGitHub) call(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	return f.fail[name]
}

func (f *fakeGitHub) PullRequest(_ context.Context, repo string, number uint32) (vcs.PRState, error) {
	if err := f.call("pull_request"); err != nil {
		return vcs.PRState{}, err
	}
	if repo != "acme/app" || number != 7 {
		return vcs.PRState{}, fmt.Errorf("unexpected read of %s#%d", repo, number)
	}
	return f.pr, nil
}

func (f *fakeGitHub) Reviews(context.Context, string, uint32) ([]vcs.ReviewState, error) {
	if err := f.call("reviews"); err != nil {
		return nil, err
	}
	return f.reviews, nil
}

// Permission resolves the login as GHES does now and refuses an account
// that is not the one asked for, as vcs.Client does.
func (f *fakeGitHub) Permission(_ context.Context, _ string, who vcs.Account) (string, error) {
	if err := f.call("permission:" + who.Login); err != nil {
		return "", err
	}
	id, ok := f.accounts[who.Login]
	switch {
	case !ok:
		return "", errors.New("GET collaborators/" + who.Login + "/permission: HTTP 404")
	case id != who.ID:
		return "", fmt.Errorf("permission reply is not about account %d: %w", who.ID, vcs.ErrAccountMismatch)
	}
	return f.perms[id], nil
}

func review(id int64, login string, account int64, state, commit string) vcs.ReviewState {
	return vcs.ReviewState{ID: id, User: vcs.Account{Login: login, ID: account}, State: state, CommitID: commit,
		SubmittedAt: time.Unix(1_800_000_000+id, 0)}
}

// authRig is the reconciler rig's store with a leased deploy of authCommit
// on acme/app#7, and the authorizer under test.
type authRig struct {
	*rig
	gh    *fakeGitHub
	cfg   AuthorizerConfig
	logs  *bytes.Buffer
	lease store.Lease
}

func newAuthRig(t *testing.T) *authRig {
	t.Helper()
	r := newRig(t)
	if err := r.reconciler().Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.engine.calls = nil // the startup inventory; the authorizer must add no step
	r.enqueue(store.JobDeploy)
	a := &authRig{rig: r, gh: newFakeGitHub(), logs: &bytes.Buffer{}}
	a.cfg = AuthorizerConfig{GitHub: a.gh, Approvals: r.queue,
		Approvers:     map[string][]validate.Approver{"acme/app": {{Login: "lead-dev", ID: approverID}}},
		ApprovalLabel: "previewd-approved", Logger: slog.New(slog.NewTextHandler(a.logs, nil))}
	return a
}

// approve records a live approval of authCommit by account (login as the
// webhook named it), as the API does on a review or a label event.
func (a *rig) approve(via store.ApprovalVia, reviewID int64, login string, account int64) {
	a.t.Helper()
	a.seq++
	id := fmt.Sprintf("approval-%d", a.seq)
	sum := sha256.Sum256([]byte(id))
	src := store.Source{Repo: "acme/app", HeadRepo: "acme/app", PRNumber: 7, OpenerLogin: "opener", OpenerID: 4242,
		CommitSHA: authCommit, CloneURL: "https://git.example.internal/acme/app.git"}
	g := store.Grant{DeliveryID: id, PayloadSHA256: hex.EncodeToString(sum[:]), EnvID: testEnv, Source: src, Seq: a.seq,
		ApproverLogin: login, ApproverID: account, Via: via, ReviewID: reviewID}
	audit := store.AuditEvent{Kind: store.AuditApprovalGranted, EnvID: testEnv, Repo: src.Repo, PRNumber: src.PRNumber,
		CommitSHA: authCommit, ActorLogin: login, ActorID: account, Detail: string(via)}
	if v, _, err := a.queue.Approve(context.Background(), g, a.now, audit); err != nil || v != store.VerdictAccepted {
		a.t.Fatalf("Approve = %s, %v", v, err)
	}
}

// approveByReview: a live grant of review 100 by lead-dev#7, still APPROVED
// on authCommit on GHES.
func (a *authRig) approveByReview() {
	a.t.Helper()
	a.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
	a.gh.reviews = []vcs.ReviewState{review(100, "lead-dev", approverID, "APPROVED", authCommit)}
}

func (a *authRig) acquire() {
	a.t.Helper()
	l, ok, err := a.queue.Acquire(context.Background(), a.now)
	if err != nil || !ok {
		a.t.Fatalf("Acquire = %v, %v", ok, err)
	}
	a.lease = l
}

func (a *authRig) authorize() (Decision, error) {
	a.t.Helper()
	if a.lease.JobID == 0 {
		a.acquire()
	}
	auth, err := NewAuthorizer(a.cfg)
	if err != nil {
		a.t.Fatal(err)
	}
	return auth.Authorize(context.Background(), a.lease)
}

// mustRefuse: the deploy is refused as not approved (parked), never
// classified, and never mistaken for an outage.
func (a *authRig) mustRefuse(why string) {
	a.t.Helper()
	d, err := a.authorize()
	if !errors.Is(err, ErrNotApproved) || errors.Is(err, ErrUnavailable) || d != (Decision{}) {
		a.t.Fatalf("%s: Authorize = %+v, %v; want ErrNotApproved only", why, d, err)
	}
}

// mustBeUntrustedApproved: an untrusted Decision on lead-dev#7's grant, which
// the store then classifies.
func (a *authRig) mustBeUntrustedApproved(why string) {
	a.t.Helper()
	d, err := a.authorize()
	if err != nil || d.Trust != store.TrustUntrusted || d.Approval == nil || d.Approval.ApproverID != approverID {
		a.t.Fatalf("%s: Authorize = %+v, %v; want untrusted on approver %d", why, d, err, approverID)
	}
	if err := a.queue.Classify(context.Background(), a.lease, store.Classification(d)); err != nil {
		a.t.Fatalf("%s: Classify = %v", why, err)
	}
}

// The trust rule: same repository and an opener with admin, maintain or
// write. GHES is the only truth: no review or permission read follows.
func TestAuthorizeTrusted(t *testing.T) {
	for _, perm := range []string{"admin", "maintain", "write"} {
		t.Run(perm, func(t *testing.T) {
			a := newAuthRig(t)
			a.gh.pr.OpenerPermission = perm
			d, err := a.authorize()
			if err != nil || d.Trust != store.TrustTrusted || d.Approval != nil {
				t.Fatalf("Authorize = %+v, %v; want trusted", d, err)
			}
			if strings.Join(a.gh.calls, ",") != "pull_request" {
				t.Fatalf("calls %v, want the pull request only", a.gh.calls)
			}
			if err := a.queue.Classify(context.Background(), a.lease, store.Classification(d)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A fork is untrusted whatever its opener's permission: without a live
// approval it is refused; with one confirmed on GHES it runs untrusted.
func TestAuthorizeForkIsUntrusted(t *testing.T) {
	a := newAuthRig(t)
	a.gh.pr.HeadRepo, a.gh.pr.OpenerPermission = "outsider/app", ""
	a.mustRefuse("fork without approval")
	a.approveByReview()
	a.mustBeUntrustedApproved("fork with a live approval")
	if want := "pull_request,reviews,permission:lead-dev"; strings.Join(a.gh.calls, ",") != "pull_request,"+want {
		t.Fatalf("calls %v", a.gh.calls)
	}
}

// A same-repository PR opened by an account without write access is
// untrusted: the queue row's head repository proves nothing.
func TestAuthorizeSameRepoReaderIsUntrusted(t *testing.T) {
	for _, perm := range []string{"triage", "read", "none", "", "WRITE", "owner"} {
		t.Run("permission="+perm, func(t *testing.T) {
			a := newAuthRig(t)
			a.gh.pr.OpenerPermission = perm
			a.mustRefuse("reader without approval")
			a.approveByReview()
			a.mustBeUntrustedApproved("reader with a live approval")
		})
	}
}

// A deleted head repository (head.repo null) is untrusted, even when the
// opener is an admin of the base repository and the queue row says the head
// lived there.
func TestAuthorizeDeletedHeadRepository(t *testing.T) {
	a := newAuthRig(t)
	a.gh.pr.HeadRepo, a.gh.pr.OpenerPermission = "", "admin"
	a.acquire()
	if a.lease.Source.HeadRepo != "acme/app" {
		t.Fatalf("lease head repository %q", a.lease.Source.HeadRepo)
	}
	a.mustRefuse("deleted head repository without approval")
	a.approveByReview()
	a.mustBeUntrustedApproved("deleted head repository with a live approval")
}

// The DB still holds a live grant (the dismissal delivery was lost or not
// yet processed), but GHES no longer reports the approval: refused.
func TestAuthorizeReviewNoLongerApproved(t *testing.T) {
	for name, reviews := range map[string][]vcs.ReviewState{
		"dismissed": {review(100, "lead-dev", approverID, "DISMISSED", authCommit)},
		"changes requested since": {review(100, "lead-dev", approverID, "APPROVED", authCommit),
			review(101, "lead-dev", approverID, "CHANGES_REQUESTED", authCommit)},
		"later change request dismissed": {review(100, "lead-dev", approverID, "APPROVED", authCommit),
			review(101, "lead-dev", approverID, "DISMISSED", authCommit)},
		"approved another commit": {review(100, "lead-dev", approverID, "APPROVED", otherCommit)},
		"approval by another account": {review(100, "lead-dev", approverID, "COMMENTED", authCommit),
			review(102, "someone", 31, "APPROVED", authCommit)},
		"no review": nil,
	} {
		t.Run(name, func(t *testing.T) {
			a := newAuthRig(t)
			a.gh.pr.HeadRepo = "outsider/app"
			a.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
			a.gh.reviews = reviews
			a.mustRefuse(name)
			if err := a.queue.Classify(context.Background(), a.lease, store.Classification{Trust: store.TrustTrusted}); err != nil {
				t.Fatal(err) // the lease is still unclassified: nothing was recorded
			}
		})
	}
}

// A comment or a pending review after an approval decides nothing.
func TestAuthorizeCommentsDoNotRevoke(t *testing.T) {
	a := newAuthRig(t)
	a.gh.pr.HeadRepo = "outsider/app"
	a.approveByReview()
	a.gh.reviews = append(a.gh.reviews, review(101, "lead-dev", approverID, "COMMENTED", authCommit),
		review(102, "lead-dev", approverID, "PENDING", authCommit))
	a.mustBeUntrustedApproved("approval followed by a comment")
}

// The approver must still hold write permission, and still be listed: a
// downgrade or a removal from PREVIEWD_APPROVERS refuses the deploy.
func TestAuthorizeApproverDowngraded(t *testing.T) {
	for _, perm := range []string{"triage", "read", "none", ""} {
		t.Run("permission "+perm, func(t *testing.T) {
			a := newAuthRig(t)
			a.gh.pr.HeadRepo = "outsider/app"
			a.approveByReview()
			a.gh.perms[approverID] = perm
			a.mustRefuse("approver downgraded to " + perm)
		})
	}
	t.Run("removed from PREVIEWD_APPROVERS", func(t *testing.T) {
		a := newAuthRig(t)
		a.gh.pr.HeadRepo = "outsider/app"
		a.approveByReview()
		a.cfg.Approvers = map[string][]validate.Approver{"acme/app": {{Login: "lead-dev", ID: 8}}}
		a.mustRefuse("approver no longer listed by ID")
		a.cfg.Approvers = map[string][]validate.Approver{"acme/other": {{Login: "lead-dev", ID: approverID}}}
		a.mustRefuse("approver listed for another repository only")
	})
	for _, perm := range []string{"admin", "maintain"} {
		t.Run("permission "+perm, func(t *testing.T) {
			a := newAuthRig(t)
			a.gh.pr.HeadRepo = "outsider/app"
			a.approveByReview()
			a.gh.perms[approverID] = perm
			a.mustBeUntrustedApproved("approver with " + perm)
		})
	}
}

// Identity is the account ID. A renamed approver still approves (the
// permission is read by the login GHES reports now, for the same ID); an
// account that took over the configured login never does.
func TestAuthorizeApproverRenamed(t *testing.T) {
	t.Run("renamed approver", func(t *testing.T) {
		a := newAuthRig(t)
		a.gh.pr.HeadRepo = "outsider/app"
		a.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
		a.gh.accounts = map[string]int64{"lead-dev-renamed": approverID}
		a.gh.reviews = []vcs.ReviewState{review(100, "lead-dev-renamed", approverID, "APPROVED", authCommit)}
		a.mustBeUntrustedApproved("approver renamed since PREVIEWD_APPROVERS was written")
		if !strings.Contains(strings.Join(a.gh.calls, ","), "permission:lead-dev-renamed") {
			t.Fatalf("calls %v: the permission must be read by the current login", a.gh.calls)
		}
		if !strings.Contains(a.logs.String(), "renamed account?") {
			t.Fatalf("the rename is not logged: %s", a.logs)
		}
	})
	t.Run("login taken over by another account", func(t *testing.T) {
		a := newAuthRig(t)
		a.gh.pr.HeadRepo = "outsider/app"
		a.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
		// lead-dev#7 renamed itself; account 99 registered "lead-dev" and
		// approved. Its review never matches approver 7.
		a.gh.accounts = map[string]int64{"lead-dev": 99, "lead-dev-renamed": approverID}
		a.gh.perms[99] = "admin"
		a.gh.reviews = []vcs.ReviewState{review(200, "lead-dev", 99, "APPROVED", authCommit)}
		a.mustRefuse("approval by the account that took over the login")
	})
	t.Run("label approval by a login now held by another account", func(t *testing.T) {
		a := newAuthRig(t)
		a.cfg.LabelApproval = true
		a.gh.pr.HeadRepo, a.gh.pr.Labels = "outsider/app", []string{"previewd-approved"}
		a.approve(store.ApprovalViaLabel, 0, "lead-dev", approverID)
		a.gh.accounts = map[string]int64{"lead-dev": 99}
		a.gh.perms[99] = "admin"
		a.mustRefuse("label grant whose login now names account 99")
	})
}

// Label approvals (D-V1-3): only with the opt-in, the label still on the
// PR, the commit still its head, and the approver with write.
func TestAuthorizeLabelApproval(t *testing.T) {
	setup := func(t *testing.T) *authRig {
		a := newAuthRig(t)
		a.cfg.LabelApproval = true
		a.gh.pr.HeadRepo, a.gh.pr.Labels = "outsider/app", []string{"bug", "previewd-approved"}
		a.approve(store.ApprovalViaLabel, 0, "lead-dev", approverID)
		return a
	}
	a := setup(t)
	a.mustBeUntrustedApproved("label approval")
	if strings.Contains(strings.Join(a.gh.calls, ","), "reviews") {
		t.Fatalf("calls %v: a label approval reads no review", a.gh.calls)
	}
	for name, mutate := range map[string]func(*authRig){
		"opt-in off":    func(a *authRig) { a.cfg.LabelApproval = false },
		"label removed": func(a *authRig) { a.gh.pr.Labels = []string{"bug"} },
		"head moved":    func(a *authRig) { a.gh.pr.HeadSHA = otherCommit },
		"downgraded":    func(a *authRig) { a.gh.perms[approverID] = "read" },
	} {
		t.Run(name, func(t *testing.T) {
			a := setup(t)
			mutate(a)
			a.mustRefuse(name)
		})
	}
}

// GHES unavailable at any read: ErrUnavailable, never a Decision and never
// ErrNotApproved (it is not parked). The lease stays unclassified, so the
// reconciler can requeue it; nothing is deployed.
func TestAuthorizeGHESUnavailable(t *testing.T) {
	outage := errors.New("dial tcp 10.0.0.5:443: connect: connection refused")
	for _, call := range []string{"pull_request", "reviews", "permission:lead-dev"} {
		for _, trustedPR := range []bool{true, false} {
			if call != "pull_request" && trustedPR {
				continue // a trusted PR reads nothing else
			}
			t.Run(fmt.Sprintf("%s trusted=%v", call, trustedPR), func(t *testing.T) {
				a := newAuthRig(t)
				if !trustedPR {
					a.gh.pr.HeadRepo = "outsider/app"
				}
				a.approveByReview()
				a.gh.fail[call] = outage
				d, err := a.authorize()
				if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotApproved) || d != (Decision{}) {
					t.Fatalf("Authorize = %+v, %v; want ErrUnavailable only", d, err)
				}
				if !errors.Is(err, outage) {
					t.Fatalf("the cause is lost: %v", err)
				}
				// Requeue, unclassified: the store accepts it only for a deploy
				// nothing classified.
				if err := a.queue.Requeue(context.Background(), a.lease, a.now.Add(time.Minute)); err != nil {
					t.Fatalf("Requeue = %v", err)
				}
				jobs, err := a.queue.Jobs(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if j := jobs[0]; j.Status != store.StatusQueued || j.Trust != store.TrustUnclassified {
					t.Fatalf("after the outage: %+v", j)
				}
				if steps := a.engine.calls; len(steps) != 0 {
					t.Fatalf("engine steps %v during an outage", steps)
				}
			})
		}
	}
	// A permission read that fails with HTTP 404 (the approver's login no
	// longer exists) is an unreadable truth too: requeued, never deployed.
	a := newAuthRig(t)
	a.gh.pr.HeadRepo = "outsider/app"
	a.approveByReview()
	a.gh.accounts = map[string]int64{}
	if d, err := a.authorize(); !errors.Is(err, ErrUnavailable) || d != (Decision{}) {
		t.Fatalf("permission 404: %+v, %v", d, err)
	}
}

// Only a deploy with a valid pull request number is ever classified, and
// the authorizer refuses to run without its dependencies.
func TestAuthorizeRefusesWhatIsNotADeploy(t *testing.T) {
	a := newAuthRig(t)
	a.acquire()
	td := a.lease
	td.Type = store.JobTeardown
	auth, err := NewAuthorizer(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := auth.Authorize(context.Background(), td); err == nil || d != (Decision{}) {
		t.Fatalf("teardown authorized: %+v", d)
	}
	for _, n := range []int64{0, -1, 1 << 32} {
		l := a.lease
		l.Source.PRNumber = n
		if d, err := auth.Authorize(context.Background(), l); err == nil || d != (Decision{}) {
			t.Errorf("PR number %d authorized: %+v", n, d)
		}
	}
	if len(a.gh.calls) != 0 {
		t.Fatalf("GHES read for an invalid lease: %v", a.gh.calls)
	}
	for name, cfg := range map[string]AuthorizerConfig{
		"no GitHub":      {Approvals: a.queue},
		"no store":       {GitHub: a.gh},
		"label, no name": {GitHub: a.gh, Approvals: a.queue, LabelApproval: true},
	} {
		if _, err := NewAuthorizer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// latestVerdict follows GHES's chronological order and ignores comments,
// pending reviews and other accounts.
func TestLatestVerdict(t *testing.T) {
	rs := []vcs.ReviewState{
		review(1, "lead-dev", approverID, "CHANGES_REQUESTED", authCommit),
		review(2, "lead-dev", approverID, "APPROVED", authCommit),
		review(3, "other", 8, "CHANGES_REQUESTED", authCommit),
		review(4, "lead-dev", approverID, "COMMENTED", authCommit),
		review(5, "lead-dev", approverID, "PENDING", authCommit),
	}
	if rv, ok := latestVerdict(rs, approverID); !ok || rv.ID != 2 {
		t.Fatalf("latestVerdict = %+v, %v; want review 2", rv, ok)
	}
	if rv, ok := latestVerdict(rs, 9); ok {
		t.Fatalf("an account without review: %+v", rv)
	}
}

// running authorizes, classifies and finishes the rig's deploy, and returns
// it as store.Running lists it: the builder the Revalidator checks.
func (a *authRig) running() store.Job {
	a.t.Helper()
	d, err := a.authorize()
	if err != nil {
		a.t.Fatalf("Authorize = %v", err)
	}
	ctx := context.Background()
	if err := a.queue.Classify(ctx, a.lease, store.Classification(d)); err != nil {
		a.t.Fatal(err)
	}
	if err := a.queue.Finish(ctx, a.lease, store.StatusSuccess, a.now); err != nil {
		a.t.Fatal(err)
	}
	jobs, err := a.queue.Running(ctx)
	if err != nil || len(jobs) != 1 {
		a.t.Fatalf("Running = %+v, %v", jobs, err)
	}
	a.gh.calls = nil
	return jobs[0]
}

func (a *authRig) revalidate(j store.Job) error {
	a.t.Helper()
	auth, err := NewAuthorizer(a.cfg)
	if err != nil {
		a.t.Fatal(err)
	}
	return auth.Revalidate(context.Background(), j)
}

// mustRevoke: Revalidate refuses with a RevokedError carrying reason.
func (a *authRig) mustRevoke(j store.Job, reason store.RevocationReason, why string) {
	a.t.Helper()
	err := a.revalidate(j)
	var rev *RevokedError
	if !errors.As(err, &rev) || !errors.Is(err, ErrNotApproved) || errors.Is(err, ErrUnavailable) || rev.Reason != reason {
		a.t.Fatalf("%s: Revalidate = %v; want a RevokedError with reason %q", why, err, reason)
	}
}

// D-V1-5: a version built trusted stays only while its PR is trusted now.
// An opener downgraded (or the head repository gone) revokes it whatever
// approval exists; there is no approval of its own to revoke.
func TestRevalidateTrustedEnvironment(t *testing.T) {
	a := newAuthRig(t)
	j := a.running()
	if j.Trust != store.TrustTrusted {
		t.Fatalf("builder trust %s", j.Trust)
	}
	if err := a.revalidate(j); err != nil {
		t.Fatalf("still trusted: %v", err)
	}
	a.gh.pr.OpenerPermission = "read" // offboarded
	a.approveByReview()               // an approval does not keep a trusted build alive
	a.mustRevoke(j, "", "opener downgraded")
	a.gh.pr.OpenerPermission, a.gh.pr.HeadRepo = "write", ""
	a.mustRevoke(j, "", "head repository deleted")

	// A version deployed before V1 (unclassified, full secret set) is judged
	// as a trusted one.
	j.Trust = store.TrustUnclassified
	a.mustRevoke(j, "", "pre-V1 version, no longer trusted")
	a.gh.pr.HeadRepo = "acme/app"
	if err := a.revalidate(j); err != nil {
		t.Fatalf("pre-V1 version, trusted: %v", err)
	}
}

// A version built on an approval stays while the approval is confirmed
// again (or the PR became trusted); each loss carries its reason.
func TestRevalidateUntrustedEnvironment(t *testing.T) {
	setup := func(t *testing.T) (*authRig, store.Job) {
		a := newAuthRig(t)
		a.gh.pr.HeadRepo = "outsider/app"
		a.approveByReview()
		j := a.running()
		if j.Trust != store.TrustUntrusted {
			t.Fatalf("builder trust %s", j.Trust)
		}
		return a, j
	}
	a, j := setup(t)
	if err := a.revalidate(j); err != nil {
		t.Fatalf("still approved: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*authRig)
		reason store.RevocationReason
	}{
		"dismissed": {func(a *authRig) {
			a.gh.reviews = []vcs.ReviewState{review(100, "lead-dev", approverID, "DISMISSED", authCommit)}
		}, store.RevokedDismissed},
		"changes requested": {func(a *authRig) {
			a.gh.reviews = append(a.gh.reviews, review(101, "lead-dev", approverID, "CHANGES_REQUESTED", authCommit))
		}, store.RevokedChangesRequested},
		"approver downgraded": {func(a *authRig) { a.gh.perms[approverID] = "read" }, store.RevokedPermissionLost},
		"login taken over":    {func(a *authRig) { a.gh.accounts = map[string]int64{"lead-dev": 99} }, store.RevokedPermissionLost},
		"approver delisted": {func(a *authRig) {
			a.cfg.Approvers = map[string][]validate.Approver{"acme/app": {{Login: "other", ID: 8}}}
		}, store.RevokedApproverRemoved},
	} {
		t.Run(name, func(t *testing.T) {
			a, j := setup(t)
			tc.mutate(a)
			a.mustRevoke(j, tc.reason, name)
		})
	}
	t.Run("approval revoked in the DB", func(t *testing.T) {
		a, j := setup(t)
		a.seq++
		if _, err := a.queue.EnqueueInternal(context.Background(), testEnv, store.OriginRevalidation, store.RevokedDismissed, a.now,
			store.AuditEvent{Kind: store.AuditTeardown, EnvID: testEnv, Repo: "acme/app", PRNumber: 7, Detail: string(store.OriginRevalidation)}); err != nil {
			t.Fatal(err)
		}
		a.mustRevoke(j, "", "no live grant")
	})
	t.Run("pull request trusted now", func(t *testing.T) {
		a, j := setup(t)
		a.gh.pr.HeadRepo = "acme/app"
		a.gh.reviews = nil
		if err := a.revalidate(j); err != nil {
			t.Fatalf("an approved version whose PR became trusted: %v", err)
		}
	})
	t.Run("GHES unavailable", func(t *testing.T) {
		for _, call := range []string{"pull_request", "reviews", "permission:lead-dev"} {
			a, j := setup(t)
			a.gh.fail[call] = errors.New("connection refused")
			if err := a.revalidate(j); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotApproved) {
				t.Fatalf("%s down: %v, want ErrUnavailable only", call, err)
			}
		}
	})
	t.Run("label removed", func(t *testing.T) {
		a := newAuthRig(t)
		a.cfg.LabelApproval = true
		a.gh.pr.HeadRepo, a.gh.pr.Labels = "outsider/app", []string{"previewd-approved"}
		a.approve(store.ApprovalViaLabel, 0, "lead-dev", approverID)
		j := a.running()
		a.gh.pr.Labels = nil
		a.mustRevoke(j, store.RevokedUnlabeled, "label removed")
	})
	t.Run("not a running version", func(t *testing.T) {
		a, j := setup(t)
		j.Status = store.StatusFailed
		if err := a.revalidate(j); err == nil || errors.Is(err, ErrNotApproved) {
			t.Fatalf("a FAILED job revalidated: %v", err)
		}
	})
}

// D-V1-1: the opt-in applies to approved untrusted deploys of the listed
// repositories only, never to a trusted one.
func TestAuthorizeFullSecretsOptIn(t *testing.T) {
	a := newAuthRig(t)
	a.cfg.FullSecretsRepos = map[string]bool{"acme/app": true}
	if d, err := a.authorize(); err != nil || d.Trust != store.TrustTrusted || d.FullSecrets {
		t.Fatalf("trusted with the opt-in listed: %+v, %v", d, err)
	}
	b := newAuthRig(t)
	b.gh.pr.HeadRepo = "outsider/app"
	b.approveByReview()
	b.cfg.FullSecretsRepos = map[string]bool{"acme/web": true}
	if d, err := b.authorize(); err != nil || d.FullSecrets {
		t.Fatalf("another repository listed: %+v, %v", d, err)
	}
	b.cfg.FullSecretsRepos = map[string]bool{"acme/app": true}
	if d, err := b.authorize(); err != nil || d.Trust != store.TrustUntrusted || !d.FullSecrets {
		t.Fatalf("listed repository: %+v, %v", d, err)
	}
}
