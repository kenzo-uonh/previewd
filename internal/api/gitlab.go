package api

// The GitLab webhook (V1.1 spec 3.1): a Merge Request Hook, authenticated by
// the shared token (VerifyWebhook), decoded by the GitLab driver, then
// recorded by the path a GitHub pull request takes. What GitLab does not
// carry is rebuilt from what it does:
//
//   - The delivery ID is X-Gitlab-Event-UUID, the replay key (the body's
//     digest is the second, as for GitHub). A GitLab that sends none gets an
//     ID derived from the body's digest; a malformed one is refused.
//   - The order of intents is the instant this host received the hook: there
//     is no time-based ID (validate.SeqAt). A retried older hook is bounded
//     by the signed window (V1-I7) and by AuthorizeDeploy, which reads the
//     forge again before anything runs.
//   - The opener is known by ID only: the login is a placeholder, identity
//     is the ID.
//
// An approval (approved) of an approver is a grant of the head its hook
// named, an unapproval (unapproved) a revocation of it (handleGitLabApproval).
// GitLab binds an approval to no commit and keeps it across a push, so the
// commit is the one the hook recorded: a new push revokes it in the store
// and the merge request needs a new approval.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// maxRecordedLogin is the longest login the audit trail keeps
// (store.maxLoginLen). A GitLab username can be longer than that; PREVIEWD_
// APPROVERS never lists one, and an approver renamed to one is recorded under
// the login configured for the account: the account ID is the identity.
const maxRecordedLogin = 39

const (
	gitlabEventHeader = "X-Gitlab-Event"
	gitlabUUIDHeader  = "X-Gitlab-Event-UUID"
)

func (s *Server) handleGitLabWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		event := r.Header.Get(gitlabEventHeader)
		if event == "" {
			http.Error(w, "missing "+gitlabEventHeader+" header", http.StatusBadRequest)
			return
		}
		if event != vcs.EventMergeRequestHook {
			// The header is unvalidated: quoted and bounded.
			s.logger.Debug("Ignoring webhook event", "event", validate.Quote(event))
			s.respond(w, http.StatusAccepted, reply{Status: "ignored"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, validate.MaxPayloadBytes+1))
		if err != nil {
			http.Error(w, "payload read failure", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		id, err := gitlabDeliveryID(r.Header.Get(gitlabUUIDHeader), digest)
		if err != nil {
			s.logger.Error("Rejected delivery ID", "error", err)
			http.Error(w, gitlabUUIDHeader+" must be a UUID", http.StatusBadRequest)
			return
		}

		ev, err := s.provider.ParseEvent(body)
		if errors.Is(err, validate.ErrIgnoredAction) {
			s.logger.Debug("Unsupported merge request action ignored", "delivery_id", id, "reason", err)
			s.respond(w, http.StatusAccepted, reply{Status: "action_ignored"})
			return
		}
		if err != nil {
			s.logger.Error("Rejected webhook payload", "delivery_id", id, "error", err)
			http.Error(w, "invalid merge request payload", http.StatusBadRequest)
			return
		}

		received := s.now()
		in := inbound{
			delivery:      validate.DeliveryID{ID: id, Seq: validate.SeqAt(received), Time: received},
			payloadSHA256: digest,
			receivedAt:    received,
		}
		if ev.Action == vcs.ActionApproved || ev.Action == vcs.ActionUnapproved {
			s.handleGitLabApproval(w, r, in, ev)
			return
		}
		s.processPullRequest(w, r, in, pullRequestOf(ev))
	}
}

// gitlabDeliveryID is the replay key of a hook: its event UUID in canonical
// form, or, when GitLab sent none, a name derived from the body's digest.
func gitlabDeliveryID(header, digest string) (string, error) {
	if header == "" {
		return "sha256-" + digest[:32], nil
	}
	return validate.GitLabEventUUID(header)
}

// pullRequestOf is ev in the shape the pull request path records.
func pullRequestOf(ev *vcs.Event) validate.PullRequest {
	return validate.PullRequest{
		Action: ev.Action, Number: ev.IID, Repo: ev.Project, HeadRef: ev.HeadRef, HeadSHA: ev.HeadSHA,
		CloneURL: ev.CloneURL, HeadRepo: ev.HeadProject, ProjectID: ev.ProjectID,
		// A hook names its author by ID only; the ID is the identity.
		OpenerLogin: "gitlab-user-" + strconv.FormatInt(ev.Author.ID, 10), OpenerID: ev.Author.ID,
		UpdatedAt: ev.UpdatedAt, SenderLogin: ev.Sender.Login, SenderID: ev.Sender.ID,
	}
}

// handleGitLabApproval records an approval or its withdrawal. Only an
// approver's counts, and never the author's own: GitLab can allow a merge
// request to approve itself, GitHub cannot, and an approval is a second pair
// of eyes. An approval is a grant of the head the hook named, with GitLab's
// truth read in the same step (trusted, open head); a withdrawal revokes
// that commit, by anyone listed, however late (it only restricts).
func (s *Server) handleGitLabApproval(w http.ResponseWriter, r *http.Request, in inbound, ev *vcs.Event) {
	pr := pullRequestOf(ev)
	envID := envid.Generate(pr.Repo, pr.HeadRef, uint64(pr.Number))
	log := s.logger.With("delivery_id", in.delivery.ID, "delivery_time", in.delivery.Time, "environment_id", envID,
		"repository", pr.Repo, "pr_number", pr.Number, "action", ev.Action, "commit_sha", ev.HeadSHA,
		"approver", ev.Sender.Login, "approver_id", ev.Sender.ID)

	approver, ok := s.approver(log, ev.Project, ev.Sender.ID, ev.Sender.Login)
	if !ok {
		log.Info("Approval event by an account that is not an approver of the project: ignored")
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}
	login := ev.Sender.Login
	if len(login) > maxRecordedLogin {
		login = approver.Login
	}
	if ev.Action == vcs.ActionUnapproved {
		if !s.signedWindow(w, log, in, ev.UpdatedAt, true) {
			return
		}
		s.revoke(w, r, in, log, envID, pr, ev.HeadSHA, store.RevokedDismissed, ev.Sender.ID, login)
		return
	}
	if ev.Author.ID == ev.Sender.ID {
		log.Warn("Approval by the author of the merge request: ignored")
		s.respond(w, http.StatusAccepted, reply{Status: "ignored", EnvironmentID: envID})
		return
	}
	if !s.signedWindow(w, log, in, ev.UpdatedAt, false) {
		return
	}
	s.grant(w, r, in, log, envID, pr, ev.HeadSHA, store.ApprovalViaMR, 0, approver.ID, login)
}
