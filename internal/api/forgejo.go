package api

// The Forgejo webhook (V1.2 spec 3.1): a pull_request or a review delivery,
// authenticated by its HMAC-SHA256 signature (VerifyWebhook), decoded by the
// Forgejo driver, then recorded by the path a GitHub pull request takes.
//
//   - The event is X-Forgejo-Event (Gitea: X-Gitea-Event); Forgejo sends
//     both, and two that disagree are refused. pull_request deploys and tears
//     down; pull_request_approved and pull_request_rejected are reviews.
//     Every other event is ignored.
//   - The delivery ID is X-Forgejo-Delivery (X-Gitea-Delivery), a UUID: the
//     replay key, with the body's digest. It is required.
//   - The order of intents is the instant this host received the delivery,
//     as for GitLab: the ID carries no time (validate.SeqAt).
//
// A review delivery says that a review was submitted and what it was, not
// its ID or the commit it was given on. An approval is therefore bound by
// reading the approver's reviews from Forgejo in the same step: their latest
// verdict must be an approval of the head the delivery names, and that
// review (its ID, commit and submission time) is what is granted. A request
// for changes revokes the head the delivery names. A dismissal sends no
// delivery: the deploy gate and the re-validation read it from Forgejo.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	forgejoEventHeader    = "X-Forgejo-Event"
	giteaEventHeader      = "X-Gitea-Event"
	forgejoDeliveryHeader = "X-Forgejo-Delivery"
	giteaDeliveryHeader   = "X-Gitea-Delivery"

	forgejoEventPullRequest = "pull_request"
	forgejoEventApproved    = "pull_request_approved"
	forgejoEventRejected    = "pull_request_rejected"

	reviewApproved = "APPROVED"
)

// Reviews is the review truth a Forgejo approval is bound with
// (vcs.Forgejo): every verdict on the pull request, in the order given.
type Reviews interface {
	Reviews(ctx context.Context, repo string, number uint32) ([]vcs.ReviewState, error)
}

// WithReviews sets the review truth of a Forgejo deployment
// (PREVIEWD_VCS_PROVIDER=forgejo), with WithProvider.
func WithReviews(r Reviews) Option {
	return func(s *Server) { s.reviews = r }
}

// forgeHeader reads a header Forgejo sends under two names: each at most
// once and, when both are present, equal. "" when neither is.
func forgeHeader(h http.Header, names ...string) (string, error) {
	var value string
	for _, name := range names {
		values := h.Values(name)
		switch {
		case len(values) > 1:
			return "", fmt.Errorf("more than one %s header", name)
		case len(values) == 0:
			continue
		case value != "" && values[0] != value:
			return "", fmt.Errorf("%s disagrees with %s", name, names[0])
		}
		value = values[0]
	}
	return value, nil
}

func (s *Server) handleForgejoWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		event, err := forgeHeader(r.Header, forgejoEventHeader, giteaEventHeader)
		switch {
		case err != nil:
			s.logger.Error("Rejected event header", "error", err)
			http.Error(w, "conflicting event headers", http.StatusBadRequest)
			return
		case event == "":
			http.Error(w, "missing "+forgejoEventHeader+" header", http.StatusBadRequest)
			return
		case event != forgejoEventPullRequest && event != forgejoEventApproved && event != forgejoEventRejected:
			// The header is unvalidated: quoted and bounded.
			s.logger.Debug("Ignoring webhook event", "event", validate.Quote(event))
			s.respond(w, http.StatusAccepted, reply{Status: "ignored"})
			return
		}
		raw, err := forgeHeader(r.Header, forgejoDeliveryHeader, giteaDeliveryHeader)
		if err != nil {
			s.logger.Error("Rejected delivery ID", "error", err)
			http.Error(w, "conflicting delivery headers", http.StatusBadRequest)
			return
		}
		id, err := validate.EventUUID(raw)
		if err != nil {
			s.logger.Error("Rejected delivery ID", "error", err)
			http.Error(w, forgejoDeliveryHeader+" must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, validate.MaxPayloadBytes+1))
		if err != nil {
			http.Error(w, "payload read failure", http.StatusBadRequest)
			return
		}
		ev, err := s.provider.ParseEvent(body)
		if errors.Is(err, validate.ErrIgnoredAction) {
			s.logger.Debug("Unsupported pull request action ignored", "delivery_id", id, "reason", err)
			s.respond(w, http.StatusAccepted, reply{Status: "action_ignored"})
			return
		}
		if err != nil {
			s.logger.Error("Rejected webhook payload", "delivery_id", id, "error", err)
			http.Error(w, "invalid pull request payload", http.StatusBadRequest)
			return
		}
		// The body is signed, the header is not: they must tell the same
		// event, so a delivery is never routed by what the signature does not
		// cover.
		want := forgejoEventPullRequest
		switch ev.Action {
		case vcs.ActionApproved:
			want = forgejoEventApproved
		case vcs.ActionChangesRequested:
			want = forgejoEventRejected
		}
		if event != want {
			s.logger.Error("Rejected delivery: the event header contradicts the signed body", "delivery_id", id,
				"event", event, "action", ev.Action)
			http.Error(w, "event header contradicts the payload", http.StatusBadRequest)
			return
		}

		sum := sha256.Sum256(body)
		received := s.now()
		in := inbound{
			delivery:      validate.DeliveryID{ID: id, Seq: validate.SeqAt(received), Time: received},
			payloadSHA256: hex.EncodeToString(sum[:]),
			receivedAt:    received,
		}
		if ev.Action == vcs.ActionApproved || ev.Action == vcs.ActionChangesRequested {
			s.handleForgejoReview(w, r, in, ev)
			return
		}
		s.processPullRequest(w, r, in, pullRequestOf(ev))
	}
}

// handleForgejoReview records an approver's review: an approval as a grant
// of the review Forgejo reports for it, a request for changes as a
// revocation of the head. Only an approver's review counts, and never the
// author's own.
func (s *Server) handleForgejoReview(w http.ResponseWriter, r *http.Request, in inbound, ev *vcs.Event) {
	pr := pullRequestOf(ev)
	envID := envid.Generate(pr.Repo, pr.HeadRef, uint64(pr.Number))
	log := s.logger.With("delivery_id", in.delivery.ID, "delivery_time", in.delivery.Time, "environment_id", envID,
		"repository", pr.Repo, "pr_number", pr.Number, "action", ev.Action, "commit_sha", ev.HeadSHA,
		"reviewer", ev.Sender.Login, "reviewer_id", ev.Sender.ID)

	approver, ok := s.approver(log, ev.Project, ev.Sender.ID, ev.Sender.Login)
	if !ok {
		log.Info("Review by an account that is not an approver of the repository: ignored")
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}
	if ev.Action == vcs.ActionChangesRequested {
		if !s.signedWindow(w, log, in, ev.UpdatedAt, true) {
			return
		}
		s.revoke(w, r, in, log, envID, pr, ev.HeadSHA, store.RevokedChangesRequested, ev.Sender.ID, ev.Sender.Login)
		return
	}
	if ev.Author.ID == ev.Sender.ID {
		log.Warn("Approval by the author of the pull request: ignored")
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), ghesTimeout)
	reviews, err := s.reviews.Reviews(ctx, pr.Repo, pr.Number)
	cancel()
	if err != nil {
		// Without the review there is nothing to bind the approval to: the
		// delivery is refused, and Forgejo can redeliver it.
		log.Error("Forgejo unavailable: the approval cannot be bound to its review (fail closed)", "error", err)
		s.respond(w, http.StatusServiceUnavailable, reply{Status: "error", EnvironmentID: envID})
		return
	}
	rv, found := latestReview(reviews, ev.Sender.ID)
	switch {
	case !found || rv.State != reviewApproved:
		log.Warn("The approver's latest review on Forgejo is not an approval: ignored", "found", found, "review_state", rv.State)
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	case rv.CommitID != ev.HeadSHA:
		log.Warn("Approval of a commit that is not the head: ignored", "review_id", rv.ID, "review_commit", rv.CommitID)
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}
	log = log.With("review_id", rv.ID)
	// The delivery carries no review time: the window (V1-I7) is that of
	// the submission Forgejo reports for the review it is bound to.
	if !s.signedWindow(w, log, in, rv.SubmittedAt, false) {
		return
	}
	s.grant(w, r, in, log, envID, pr, rv.CommitID, store.ApprovalViaReview, rv.ID, approver.ID, rv.User.Login)
}

// latestReview returns account id's latest verdict, in the order Forgejo
// gave them.
func latestReview(reviews []vcs.ReviewState, id int64) (vcs.ReviewState, bool) {
	var last vcs.ReviewState
	found := false
	for _, rv := range reviews {
		if rv.User.ID == id {
			last, found = rv, true
		}
	}
	return last, found
}
