package orchestrator

// Developer feedback (V1.1 spec 3.3): the commit status and the sticky
// comment that follow a deploy. It is a courtesy, never a dependency: every
// error, and every hang, of the forge is logged here and nowhere else, and
// the deploy goes on exactly as if feedback were off.

import (
	"context"
	"log/slog"
	"time"

	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// Feedback tells the forge where a deploy stands. *vcs.Notifier implements
// it. A nil Feedback in ReconcilerConfig turns the loop off.
type Feedback interface {
	// Begin: the deploy was authorized and starts (status pending).
	Begin(ctx context.Context, s vcs.Status) error
	// Succeed: the environment runs and the database says so (status
	// success, sticky comment with the URL).
	Succeed(ctx context.Context, s vcs.Status) error
	// Fail: the deploy failed and was rolled back; s.Failure names the step
	// (status failure, sticky comment turned red).
	Fail(ctx context.Context, s vcs.Status) error
}

const (
	defaultFeedbackTimeout = 10 * time.Second
	maxFeedbackTimeout     = time.Minute
	defaultPreviewScheme   = "http"
	// failureSetup names a failure outside the closed vocabulary of
	// store.Failure (removing the previous version, the network): the
	// comment must still say it failed.
	failureSetup = "setup"
)

// status describes the deploy of l for the developer.
func (r *Reconciler) status(l store.Lease, d Decision) vcs.Status {
	s := vcs.Status{
		Repo: l.Source.Repo, PRNumber: l.Source.PRNumber, CommitSHA: l.Source.CommitSHA,
		URL: r.cfg.PreviewScheme + "://" + l.EnvID + "." + r.cfg.Domain,
	}
	if d.Approval != nil {
		s.Approver, s.ApproverID = d.Approval.ApproverLogin, d.Approval.ApproverID
	}
	if !r.cfg.DisableTTL {
		s.Expires = r.cfg.Now().Add(r.cfg.EnvTTL)
	}
	return s
}

// notify runs one feedback call on a context that outlives a cancelled job
// and ends at FeedbackTimeout. Its error is logged at Warn and dropped: the
// deploy never fails, aborts or waits longer for the forge's answer.
func (r *Reconciler) notify(ctx context.Context, log *slog.Logger, what string, call func(context.Context) error) {
	if r.cfg.Feedback == nil {
		return
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.cfg.FeedbackTimeout)
	defer cancel()
	if err := call(fctx); err != nil {
		log.Warn("Developer feedback not delivered: the deploy is not affected", "feedback", what, "error", err)
	}
}
