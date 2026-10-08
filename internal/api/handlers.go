package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	// maxDeliverySkew bounds how far ahead of this host's clock a delivery
	// timestamp may be. The X-GitHub-Delivery header is not signed: without
	// a bound, one forged far-future ID would make every later event of the
	// environment stale.
	maxDeliverySkew = 5 * time.Minute

	// signedTimeLead is how far a delivery GUID may precede the signed time
	// of its body (V1-I7): GHES mints the GUID and stamps the payload within
	// one event, on clocks the installation keeps on NTP.
	signedTimeLead = 5 * time.Minute

	// enqueueTimeout bounds the queue write, which runs even if the client
	// disconnects: a delivery is either recorded or answered with an error.
	enqueueTimeout = 10 * time.Second

	// ghesTimeout bounds the GHES reads one approval or revocation needs.
	ghesTimeout = 5 * time.Second
)

// Queue records deliveries (store.Store).
type Queue interface {
	Enqueue(ctx context.Context, d store.Delivery) (store.Verdict, int64, error)
	Approve(ctx context.Context, g store.Grant, now time.Time, audit store.AuditEvent) (store.Verdict, int64, error)
	Revoke(ctx context.Context, r store.Revoke, now time.Time, audit store.AuditEvent) (store.Verdict, int64, error)
}

// GitHub is the GHES truth read in the step that records an approval or a
// revocation (V1 spec 3.4): whether the environment is trusted (the head
// lives in the base repository and its opener can write there, D-V1-5) and
// whether the approved commit is the open head. The client is phase C3.
// Without it, or when a read fails, the handler fails closed: an approval is
// recorded but queues no deploy, and a revocation is judged as for an
// untrusted environment.
type GitHub interface {
	PullRequest(ctx context.Context, repo string, number uint32) (vcs.PRState, error)
	Permission(ctx context.Context, repo, login string) (string, error)
}

// Waker is told when a job was queued (orchestrator.Reconciler).
type Waker interface {
	Notify()
}

// Server encapsulates dependencies for ingress routing and orchestration triggers.
type Server struct {
	logger *slog.Logger
	cfg    *config.Config
	queue  Queue
	waker  Waker
	github GitHub // nil until the GHES client (C3) is configured
	now    func() time.Time
}

// NewServer initializes the HTTP API controller. github may be nil: see
// GitHub.
func NewServer(logger *slog.Logger, cfg *config.Config, queue Queue, waker Waker, github GitHub) *Server {
	return &Server{logger: logger, cfg: cfg, queue: queue, waker: waker, github: github, now: time.Now}
}

// Routes constructs the mux router with signature verification middleware.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthCheck())

	webhookHandler := http.HandlerFunc(s.handleGitHubWebhook())
	mux.Handle("POST /webhooks/github", ValidateGitHubSignature([]byte(s.cfg.WebhookSecret))(webhookHandler))

	return mux
}

type reply struct {
	Status        string `json:"status"`
	EnvironmentID string `json:"environment_id,omitempty"`
	JobID         int64  `json:"job_id,omitempty"`
}

func (s *Server) respond(w http.ResponseWriter, status int, body reply) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.Error("Failed to write HTTP response", "error", err)
	}
}

func (s *Server) handleHealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, http.StatusOK, reply{Status: "healthy"})
	}
}

func (s *Server) handleGitHubWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		event := r.Header.Get("X-GitHub-Event")
		if event == "" {
			http.Error(w, "missing X-GitHub-Event header", http.StatusBadRequest)
			return
		}

		if event == vcs.EventPing {
			s.logger.Info("Ingested GitHub ping handshake")
			s.respond(w, http.StatusOK, reply{Status: "pong"})
			return
		}

		if event != vcs.EventPullRequest && event != vcs.EventPullRequestReview {
			s.logger.Debug("Ignoring webhook event", "event", event)
			s.respond(w, http.StatusAccepted, reply{Status: "ignored"})
			return
		}

		delivery, err := validate.ParseDeliveryID(r.Header.Get(validate.DeliveryHeader))
		if err != nil {
			s.logger.Error("Rejected delivery ID", "error", err)
			http.Error(w, "X-GitHub-Delivery must be a UUID version 1", http.StatusBadRequest)
			return
		}
		if now := s.now(); delivery.Time.After(now.Add(maxDeliverySkew)) {
			s.logger.Error("Rejected delivery timestamped in the future",
				"delivery_id", delivery.ID, "delivery_time", delivery.Time, "now", now, "max_skew", maxDeliverySkew)
			http.Error(w, "delivery timestamp is in the future", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, validate.MaxPayloadBytes+1))
		if err != nil {
			http.Error(w, "payload read failure", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		in := inbound{delivery: delivery, payloadSHA256: hex.EncodeToString(sum[:]), receivedAt: s.now()}
		if event == vcs.EventPullRequestReview {
			s.handleReview(w, r, in, body)
			return
		}
		s.handlePullRequest(w, r, in, body)
	}
}

// inbound is one authenticated delivery: its ordering and replay keys.
type inbound struct {
	delivery      validate.DeliveryID
	payloadSHA256 string
	receivedAt    time.Time
}

// signedWindow is V1-I7: the unsigned delivery GUID's time must lie within
// [signed - 5 min, signed + PREVIEWD_DELIVERY_MAX_AGE] of the time the
// signed body carries. A captured body resent later under a fresh GUID falls
// outside it, so it cannot return as a new intent once its delivery row is
// pruned. A delivery that would grant or deploy is refused outside the
// window (400, logged). One that only restricts (a teardown, a revocation)
// is processed anyway and logged: refusing it could keep alive what GitHub
// withdrew, and replaying it can only remove.
func (s *Server) signedWindow(w http.ResponseWriter, log *slog.Logger, in inbound, signed time.Time, restrictive bool) bool {
	t := in.delivery.Time
	if !t.Before(signed.Add(-signedTimeLead)) && !t.After(signed.Add(s.cfg.DeliveryMaxAge)) {
		return true
	}
	if restrictive {
		log.Warn("Delivery time outside its signed window: processed, it only restricts",
			"signed_time", signed, "max_age", s.cfg.DeliveryMaxAge)
		return true
	}
	log.Error("Rejected delivery: its time is outside the signed payload window (V1-I7)",
		"signed_time", signed, "max_age", s.cfg.DeliveryMaxAge)
	http.Error(w, "delivery time outside the signed payload window", http.StatusBadRequest)
	return false
}

// storeContext outlives the request: a delivery is recorded or answered
// with an error, never half-written.
func storeContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), enqueueTimeout)
}

func (s *Server) handlePullRequest(w http.ResponseWriter, r *http.Request, in inbound, body []byte) {
	pr, err := validate.ParsePullRequest(body)
	if errors.Is(err, validate.ErrIgnoredAction) {
		s.logger.Debug("Unsupported PR action ignored", "pr_number", pr.Number, "repository", pr.Repo)
		s.respond(w, http.StatusAccepted, reply{Status: "action_ignored"})
		return
	}
	if err != nil {
		s.logger.Error("Rejected webhook payload", "delivery_id", in.delivery.ID, "error", err)
		http.Error(w, "invalid pull_request payload", http.StatusBadRequest)
		return
	}

	envID := envid.Generate(pr.Repo, pr.HeadRef, uint64(pr.Number))
	log := s.logger.With("delivery_id", in.delivery.ID, "delivery_time", in.delivery.Time, "environment_id", envID,
		"repository", pr.Repo, "pr_number", pr.Number, "action", pr.Action, "commit_sha", pr.HeadSHA)

	if pr.Action == validate.ActionLabeled || pr.Action == validate.ActionUnlabeled {
		s.handleLabel(w, r, in, pr, envID, log)
		return
	}
	typ := store.JobDeploy
	if pr.Action == validate.ActionClosed {
		typ = store.JobTeardown
	}
	if !s.signedWindow(w, log, in, pr.UpdatedAt, typ == store.JobTeardown) {
		return
	}
	d := store.Delivery{
		ID:            in.delivery.ID,
		PayloadSHA256: in.payloadSHA256,
		EnvID:         envID,
		Type:          typ,
		Seq:           in.delivery.Seq,
		Source:        source(pr, pr.HeadSHA),
		ReceivedAt:    in.receivedAt,
	}

	ctx, cancel := storeContext(r)
	defer cancel()
	verdict, jobID, err := s.queue.Enqueue(ctx, d)
	if err != nil {
		log.Error("Could not record the delivery", "error", err)
		s.respond(w, http.StatusInternalServerError, reply{Status: "error"})
		return
	}

	switch verdict {
	case store.VerdictAccepted:
		log.Info("Job queued", "job_id", jobID, "type", string(typ))
		s.waker.Notify()
		s.respond(w, http.StatusAccepted, reply{Status: "queued", EnvironmentID: envID, JobID: jobID})
	case store.VerdictStale:
		log.Warn("Stale delivery: a newer intent is already recorded for this environment")
		s.respond(w, http.StatusAccepted, reply{Status: "stale", EnvironmentID: envID})
	default:
		log.Info("Duplicate delivery ignored")
		s.respond(w, http.StatusOK, reply{Status: "duplicate", EnvironmentID: envID})
	}
}

// source is the job source of pr at commit.
func source(pr validate.PullRequest, commit string) store.Source {
	return store.Source{
		Repo:        pr.Repo,
		HeadRepo:    pr.HeadRepo,
		PRNumber:    int64(pr.Number),
		OpenerLogin: pr.OpenerLogin,
		OpenerID:    pr.OpenerID,
		CommitSHA:   commit,
		CloneURL:    pr.CloneURL,
	}
}
