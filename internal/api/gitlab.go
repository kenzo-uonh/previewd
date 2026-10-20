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
// Approvals (approved, unapproved) are acknowledged and not recorded yet:
// an untrusted merge request does not deploy, which is the fail-closed side.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

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
			s.logger.Warn("GitLab approval event not recorded: approvals are not supported for GitLab yet, the merge request is not authorized by it",
				"delivery_id", id, "repository", ev.Project, "mr_iid", ev.IID, "action", ev.Action,
				"approver", ev.Sender.Login, "approver_id", ev.Sender.ID)
			s.respond(w, http.StatusAccepted, reply{Status: "unsupported"})
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
		CloneURL: ev.CloneURL, HeadRepo: ev.HeadProject,
		// A hook names its author by ID only; the ID is the identity.
		OpenerLogin: "gitlab-user-" + strconv.FormatInt(ev.Author.ID, 10), OpenerID: ev.Author.ID,
		UpdatedAt: ev.UpdatedAt, SenderLogin: ev.Sender.Login, SenderID: ev.Sender.ID,
	}
}
