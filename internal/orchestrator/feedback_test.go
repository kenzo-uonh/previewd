package orchestrator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

type fbCall struct {
	step string
	s    vcs.Status
}

// fakeFeedback records the calls and, when err is set, fails each of them.
type fakeFeedback struct {
	mu    sync.Mutex
	calls []fbCall
	err   error
	// block makes a call wait for its context, as a hung forge does.
	block bool
	// onCall observes the recorded state at the time of a call.
	onCall func(step string)
}

func (f *fakeFeedback) record(ctx context.Context, step string, s vcs.Status) error {
	if f.onCall != nil {
		f.onCall(step)
	}
	f.mu.Lock()
	f.calls = append(f.calls, fbCall{step, s})
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.err
}

func (f *fakeFeedback) Begin(ctx context.Context, s vcs.Status) error {
	return f.record(ctx, "begin", s)
}
func (f *fakeFeedback) Succeed(ctx context.Context, s vcs.Status) error {
	return f.record(ctx, "succeed", s)
}
func (f *fakeFeedback) Fail(ctx context.Context, s vcs.Status) error { return f.record(ctx, "fail", s) }

func (f *fakeFeedback) steps() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.step)
	}
	return strings.Join(out, ",")
}

func TestFeedbackFollowsASuccessfulDeploy(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{}
	r.feedback = fb
	rec := r.started()
	r.enqueue(store.JobDeploy)
	if jobs := r.drain(rec); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("jobs = %+v", jobs)
	}
	if got := fb.steps(); got != "begin,succeed" {
		t.Fatalf("feedback = %s, want begin,succeed", got)
	}
	want := vcs.Status{
		Repo: "acme/app", PRNumber: 7, CommitSHA: "0123456789abcdef0123456789abcdef01234567",
		URL:     "http://" + testEnv + ".local.previewd",
		Expires: r.now.Add(defaultEnvTTL),
	}
	for _, c := range fb.calls {
		if c.s != want {
			t.Errorf("%s status = %+v\nwant %+v", c.step, c.s, want)
		}
	}
}

// The success is announced after the database records it, and the pending
// status before anything is built.
func TestFeedbackOrderAgainstTheDeploy(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{}
	var atBegin, atSucceed store.JobStatus
	fb.onCall = func(step string) {
		jobs, err := r.queue.Jobs(context.Background())
		if err != nil || len(jobs) == 0 {
			t.Errorf("jobs: %v", err)
			return
		}
		switch step {
		case "begin":
			atBegin = jobs[len(jobs)-1].Status
			if r.built() {
				t.Error("begin ran after the build started")
			}
		case "succeed":
			atSucceed = jobs[len(jobs)-1].Status
		}
	}
	r.feedback = fb
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	if atBegin != store.StatusInProgress || atSucceed != store.StatusSuccess {
		t.Errorf("job at begin %s, at succeed %s; want IN_PROGRESS then SUCCESS", atBegin, atSucceed)
	}
}

func TestFeedbackNamesTheApproverOfAnUntrustedDeploy(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{}
	r.feedback = fb
	rec := r.started()
	r.approve(store.ApprovalViaReview, 100, "lead-dev", approverID)
	r.auth.set(r.untrusted(false), nil)
	r.enqueue(store.JobDeploy)
	if lastStatus(r.drain(rec)) != store.StatusSuccess {
		t.Fatal("untrusted deploy failed")
	}
	if len(fb.calls) != 2 || fb.calls[1].s.Approver != "lead-dev" || fb.calls[1].s.ApproverID != approverID {
		t.Fatalf("calls = %+v", fb.calls)
	}
}

func TestFeedbackWithoutTTLHasNoExpiry(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{}
	r.feedback, r.disableTTL = fb, true
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	if len(fb.calls) != 2 || !fb.calls[1].s.Expires.IsZero() {
		t.Fatalf("calls = %+v", fb.calls)
	}
}

func TestFeedbackUsesThePreviewScheme(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{}
	r.feedback, r.previewScheme = fb, "https"
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	if len(fb.calls) == 0 || fb.calls[0].s.URL != "https://"+testEnv+".local.previewd" {
		t.Fatalf("calls = %+v", fb.calls)
	}
}

// Each failing step is reported with its name, after the rollback.
func TestFeedbackOfAFailedDeployNamesTheStep(t *testing.T) {
	for step, want := range map[string]string{
		"fetch": "fetch", "preflight": "preflight", "build": "build", "stage": "stage",
		"deploy": "start", "publish": "route", "network": "setup",
	} {
		t.Run(step, func(t *testing.T) {
			r := newRig(t)
			fb := &fakeFeedback{}
			r.feedback = fb
			boom := errors.New(step + " failed")
			switch step {
			case "fetch":
				r.fetchErr = boom
			case "preflight":
				r.dockerfile = "FROM busybox:latest\n"
			case "stage":
				r.stager.failErr = boom
			case "publish":
				r.routes = failingPublish{RoutePublisher: r.routes, err: boom}
			default:
				r.engine.fail[step] = boom
			}
			fb.onCall = func(s string) {
				if s == "fail" && (len(r.engine.envs) != 0 || len(r.routeFiles()) != 0) {
					t.Errorf("fail announced before the rollback: engine %v routes %v", r.engine.envs, r.routeFiles())
				}
			}
			rec := r.started()
			r.enqueue(store.JobDeploy)
			if lastStatus(r.drain(rec)) != store.StatusFailed {
				t.Fatal("deploy did not fail")
			}
			if got := fb.steps(); got != "begin,fail" {
				t.Fatalf("feedback = %s, want begin,fail", got)
			}
			if got := fb.calls[1].s.Failure; got != want {
				t.Errorf("failure = %q, want %q", got, want)
			}
		})
	}
}

// Fail open (spec 3.3): feedback that errors, at any point, changes nothing
// about the deploy.
func TestFeedbackErrorsNeverFailTheDeploy(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{err: errors.New("403 resource not accessible")}
	r.feedback = fb
	rec := r.started()
	r.enqueue(store.JobDeploy)
	if jobs := r.drain(rec); lastStatus(jobs) != store.StatusSuccess || jobs[len(jobs)-1].Failure != store.FailureNone {
		t.Fatalf("jobs = %+v; want SUCCESS", jobs)
	}
	if got := fb.steps(); got != "begin,succeed" {
		t.Errorf("feedback = %s: an error in begin must not skip the rest", got)
	}
	if !r.running() || len(r.routeFiles()) != 1 {
		t.Errorf("environment not running: routes %v", r.routeFiles())
	}
}

func TestFeedbackErrorsDoNotChangeAFailedDeploy(t *testing.T) {
	r := newRig(t)
	r.feedback = &fakeFeedback{err: errors.New("boom")}
	r.engine.fail["build"] = errors.New("build failed")
	rec := r.started()
	r.enqueue(store.JobDeploy)
	jobs := r.drain(rec)
	if lastStatus(jobs) != store.StatusFailed || jobs[len(jobs)-1].Failure != store.FailureBuild {
		t.Fatalf("jobs = %+v; want FAILED at build", jobs)
	}
}

// A forge that hangs costs the deploy at most the feedback timeout.
func TestFeedbackHangIsBounded(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{block: true}
	r.feedback, r.feedbackTimeout = fb, 50*time.Millisecond
	rec := r.started()
	r.enqueue(store.JobDeploy)
	start := time.Now()
	if jobs := r.drain(rec); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("jobs = %+v", jobs)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("deploy took %s behind a hung forge", took)
	}
	if got := fb.steps(); got != "begin,succeed" {
		t.Errorf("feedback = %s", got)
	}
}

// Teardowns and a deploy that was never authorized say nothing: there is no
// preview to announce.
func TestFeedbackIsSilentWithoutADeploy(t *testing.T) {
	r := newRig(t)
	fb := &fakeFeedback{}
	r.feedback = fb
	r.auth.authorize = func(store.Lease) (Decision, error) { return Decision{}, refuse("", "no live approval") }
	rec := r.started()
	r.enqueue(store.JobDeploy)
	r.drain(rec)
	r.enqueue(store.JobTeardown)
	r.drain(rec)
	if got := fb.steps(); got != "" {
		t.Errorf("feedback = %s; want none", got)
	}
}

func TestReconcilerWithoutFeedbackDeploys(t *testing.T) {
	r := newRig(t)
	rec := r.started()
	r.enqueue(store.JobDeploy)
	if lastStatus(r.drain(rec)) != store.StatusSuccess {
		t.Fatal("deploy without feedback failed")
	}
}

func TestNewReconcilerValidatesFeedbackSettings(t *testing.T) {
	for name, edit := range map[string]func(*rig){
		"scheme ftp":       func(r *rig) { r.previewScheme = "ftp" },
		"scheme uppercase": func(r *rig) { r.previewScheme = "HTTPS" },
		"negative timeout": func(r *rig) { r.feedbackTimeout = -time.Second },
		"huge timeout":     func(r *rig) { r.feedbackTimeout = time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			edit(r)
			_, err := NewReconciler(r.config())
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
