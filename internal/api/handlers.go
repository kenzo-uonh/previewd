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

	// enqueueTimeout bounds the queue write, which runs even if the client
	// disconnects: a delivery is either recorded or answered with an error.
	enqueueTimeout = 10 * time.Second
)

// Queue records deliveries (store.Store).
type Queue interface {
	Enqueue(ctx context.Context, d store.Delivery) (store.Verdict, int64, error)
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
	now    func() time.Time
}

// NewServer initializes the HTTP API controller.
func NewServer(logger *slog.Logger, cfg *config.Config, queue Queue, waker Waker) *Server {
	return &Server{logger: logger, cfg: cfg, queue: queue, waker: waker, now: time.Now}
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

		if event != vcs.EventPullRequest {
			s.logger.Debug("Ignoring non-PR webhook event", "event", event)
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
		pr, err := validate.ParsePullRequest(body)
		if errors.Is(err, validate.ErrIgnoredAction) {
			s.logger.Debug("Unsupported PR action ignored", "pr_number", pr.Number, "repository", pr.Repo)
			s.respond(w, http.StatusAccepted, reply{Status: "action_ignored"})
			return
		}
		if err != nil {
			s.logger.Error("Rejected webhook payload", "delivery_id", delivery.ID, "error", err)
			http.Error(w, "invalid pull_request payload", http.StatusBadRequest)
			return
		}

		envID := envid.Generate(pr.Repo, pr.HeadRef, uint64(pr.Number))
		typ := store.JobDeploy
		if pr.Action == validate.ActionClosed {
			typ = store.JobTeardown
		}
		sum := sha256.Sum256(body)
		d := store.Delivery{
			ID:            delivery.ID,
			PayloadSHA256: hex.EncodeToString(sum[:]),
			EnvID:         envID,
			Type:          typ,
			Seq:           delivery.Seq,
			Source: store.Source{
				Repo:        pr.Repo,
				HeadRepo:    pr.HeadRepo,
				PRNumber:    int64(pr.Number),
				OpenerLogin: pr.OpenerLogin,
				OpenerID:    pr.OpenerID,
				CommitSHA:   pr.HeadSHA,
				CloneURL:    pr.CloneURL,
			},
			ReceivedAt: s.now(),
		}
		log := s.logger.With("delivery_id", delivery.ID, "delivery_time", delivery.Time, "environment_id", envID,
			"repository", pr.Repo, "pr_number", pr.Number, "action", pr.Action, "commit_sha", pr.HeadSHA)

		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), enqueueTimeout)
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
}
