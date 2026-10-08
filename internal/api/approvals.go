package api

// The approval rows of the webhook event matrix (V1 spec 3.3): reviews and
// the approval label. Every approval is bound to an exact commit and to the
// approver's account ID (V1-I3); the store records it with its delivery,
// replay-checked, and its audit row in one transaction.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// approver returns the PREVIEWD_APPROVERS entry of repo for account id. The
// account ID is the identity; a login that differs (a renamed account) is
// logged and accepted.
func (s *Server) approver(log *slog.Logger, repo string, id int64, login string) (validate.Approver, bool) {
	for _, a := range s.cfg.Approvers[repo] {
		if a.ID == id {
			if a.Login != login {
				log.Warn("Approver login differs from PREVIEWD_APPROVERS (renamed account?): matched on the account ID",
					"approver_id", id, "login", login, "configured_login", a.Login)
			}
			return a, true
		}
	}
	return validate.Approver{}, false
}

// truth reads GHES in the step that records an approval or a revocation:
// whether the environment is trusted, and whether commit is the open head.
// Without the client, or on any failed read, both are false: no approval
// queues a deploy, and a revocation is judged as for an untrusted
// environment. AuthorizeDeploy reads GHES again before anything runs.
func (s *Server) truth(r *http.Request, log *slog.Logger, repo string, number uint32, commit string) (trusted, openHead bool) {
	if s.github == nil {
		log.Warn("No GHES client: approval judged without GitHub truth (fail closed)")
		return false, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), ghesTimeout)
	defer cancel()
	pr, err := s.github.PullRequest(ctx, repo, number)
	if err != nil {
		log.Warn("GHES unavailable: approval judged without GitHub truth (fail closed)", "error", err)
		return false, false
	}
	openHead = pr.Open && pr.HeadSHA == commit
	if pr.HeadRepo != repo || pr.OpenerLogin == "" {
		return false, openHead
	}
	permission, err := s.github.Permission(ctx, repo, pr.OpenerLogin)
	if err != nil {
		log.Warn("GHES unavailable: opener permission unknown, judged untrusted (fail closed)", "error", err)
		return false, openHead
	}
	return vcs.Trusted(pr, repo, permission), openHead
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request, in inbound, body []byte) {
	rv, err := validate.ParseReview(body)
	if errors.Is(err, validate.ErrIgnoredAction) {
		s.logger.Debug("Review ignored", "pr_number", rv.Number, "repository", rv.Repo, "action", rv.Action, "state", rv.State)
		s.respond(w, http.StatusAccepted, reply{Status: "action_ignored"})
		return
	}
	if err != nil {
		s.logger.Error("Rejected webhook payload", "delivery_id", in.delivery.ID, "error", err)
		http.Error(w, "invalid pull_request_review payload", http.StatusBadRequest)
		return
	}

	envID := envid.Generate(rv.Repo, rv.HeadRef, uint64(rv.Number))
	log := s.logger.With("delivery_id", in.delivery.ID, "delivery_time", in.delivery.Time, "environment_id", envID,
		"repository", rv.Repo, "pr_number", rv.Number, "review_action", rv.Action, "review_state", rv.State,
		"review_id", rv.ReviewID, "reviewer", rv.ReviewerLogin, "reviewer_id", rv.ReviewerID, "commit_sha", rv.CommitSHA)

	// Only an approver's review counts, approving or withdrawn: another
	// account's review was never a grant.
	approver, ok := s.approver(log, rv.Repo, rv.ReviewerID, rv.ReviewerLogin)
	if !ok {
		log.Info("Review by an account that is not an approver of the repository: ignored")
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}

	switch {
	case rv.Action == validate.ActionSubmitted && rv.State == validate.ReviewApproved:
		if rv.CommitSHA != rv.HeadSHA {
			log.Warn("Approval of a commit that is not the head: ignored", "head_sha", rv.HeadSHA)
			s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
			return
		}
		if !s.signedWindow(w, log, in, rv.SubmittedAt, false) {
			return
		}
		s.grant(w, r, in, log, envID, rv.PullRequest, rv.CommitSHA, store.ApprovalViaReview, rv.ReviewID,
			approver.ID, rv.ReviewerLogin)
	case rv.Action == validate.ActionSubmitted:
		if !s.signedWindow(w, log, in, rv.SubmittedAt, true) {
			return
		}
		s.revoke(w, r, in, log, envID, rv.PullRequest, rv.CommitSHA, store.RevokedChangesRequested, rv.ReviewerID, rv.ReviewerLogin)
	default:
		// A dismissal carries the original submitted_at; the pull
		// request's updated_at moves with it. The actor is who dismissed.
		if !s.signedWindow(w, log, in, rv.UpdatedAt, true) {
			return
		}
		s.revoke(w, r, in, log, envID, rv.PullRequest, rv.CommitSHA, store.RevokedDismissed, rv.SenderID, rv.SenderLogin)
	}
}

// handleLabel is the label path (D-V1-3), only with PREVIEWD_LABEL_APPROVAL
// and only for PREVIEWD_APPROVAL_LABEL: an approver's label approves the
// head at the time of labeling; removing it, by anyone, revokes that head.
func (s *Server) handleLabel(w http.ResponseWriter, r *http.Request, in inbound, pr validate.PullRequest, envID string, log *slog.Logger) {
	if !s.cfg.LabelApproval || pr.Label != s.cfg.ApprovalLabel {
		log.Debug("Label ignored", "label", pr.Label)
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}
	log = log.With("label", pr.Label, "sender", pr.SenderLogin, "sender_id", pr.SenderID)
	if pr.Action == validate.ActionUnlabeled {
		if !s.signedWindow(w, log, in, pr.UpdatedAt, true) {
			return
		}
		s.revoke(w, r, in, log, envID, pr, pr.HeadSHA, store.RevokedUnlabeled, pr.SenderID, pr.SenderLogin)
		return
	}
	approver, ok := s.approver(log, pr.Repo, pr.SenderID, pr.SenderLogin)
	if !ok {
		log.Warn("Approval label set by an account that is not an approver of the repository: ignored")
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}
	if !s.signedWindow(w, log, in, pr.UpdatedAt, false) {
		return
	}
	s.grant(w, r, in, log, envID, pr, pr.HeadSHA, store.ApprovalViaLabel, 0, approver.ID, pr.SenderLogin)
}

// grant records an approval of commit by approverID (login as it is now).
func (s *Server) grant(w http.ResponseWriter, r *http.Request, in inbound, log *slog.Logger, envID string,
	pr validate.PullRequest, commit string, via store.ApprovalVia, reviewID, approverID int64, login string) {
	trusted, openHead := s.truth(r, log, pr.Repo, pr.Number, commit)
	g := store.Grant{
		DeliveryID: in.delivery.ID, PayloadSHA256: in.payloadSHA256, EnvID: envID, Source: source(pr, commit),
		Seq: in.delivery.Seq, ApproverLogin: login, ApproverID: approverID, Via: via, ReviewID: reviewID,
		Trusted: trusted, OpenHead: openHead,
	}
	audit := store.AuditEvent{Kind: store.AuditApprovalGranted, EnvID: envID, Repo: pr.Repo, PRNumber: int64(pr.Number),
		CommitSHA: commit, ActorLogin: login, ActorID: approverID, Detail: string(via)}
	ctx, cancel := storeContext(r)
	defer cancel()
	verdict, jobID, err := s.queue.Approve(ctx, g, in.receivedAt, audit)
	s.recorded(w, log.With("trusted", trusted, "open_head", openHead), envID, "approval", verdict, jobID, err)
}

// revoke records a revocation of commit, attributed to actorID.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, in inbound, log *slog.Logger, envID string,
	pr validate.PullRequest, commit string, reason store.RevocationReason, actorID int64, login string) {
	trusted, _ := s.truth(r, log, pr.Repo, pr.Number, commit)
	rv := store.Revoke{
		DeliveryID: in.delivery.ID, PayloadSHA256: in.payloadSHA256, EnvID: envID, Repo: pr.Repo,
		PRNumber: int64(pr.Number), CommitSHA: commit, Seq: in.delivery.Seq, Reason: reason, Trusted: trusted,
	}
	audit := store.AuditEvent{Kind: store.AuditApprovalRevoked, EnvID: envID, Repo: pr.Repo, PRNumber: int64(pr.Number),
		CommitSHA: commit, ActorLogin: login, ActorID: actorID, Detail: string(reason)}
	ctx, cancel := storeContext(r)
	defer cancel()
	verdict, jobID, err := s.queue.Revoke(ctx, rv, in.receivedAt, audit)
	s.recorded(w, log.With("trusted", trusted, "reason", string(reason)), envID, "revocation", verdict, jobID, err)
}

// recorded answers an approval or a revocation once the store has it.
func (s *Server) recorded(w http.ResponseWriter, log *slog.Logger, envID, what string, verdict store.Verdict, jobID int64, err error) {
	switch {
	case err != nil:
		log.Error("Could not record the "+what, "error", err)
		s.respond(w, http.StatusInternalServerError, reply{Status: "error"})
	case verdict == store.VerdictReplay:
		log.Info("Duplicate " + what + " ignored")
		s.respond(w, http.StatusOK, reply{Status: "duplicate", EnvironmentID: envID})
	case jobID != 0:
		log.Info(what+" recorded, job queued", "job_id", jobID)
		s.waker.Notify()
		s.respond(w, http.StatusAccepted, reply{Status: "queued", EnvironmentID: envID, JobID: jobID})
	default:
		log.Info(what + " recorded")
		s.respond(w, http.StatusAccepted, reply{Status: "recorded", EnvironmentID: envID})
	}
}
