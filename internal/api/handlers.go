package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// Server encapsulates dependencies for ingress routing and orchestration triggers.
type Server struct {
	logger *slog.Logger
	cfg    *config.Config
	store  *store.Store
	engine orchestrator.Engine
	stager orchestrator.SecretStager
	pool   *orchestrator.WorkerPool
}

// NewServer initializes the HTTP API controller.
func NewServer(
	logger *slog.Logger,
	cfg *config.Config,
	store *store.Store,
	engine orchestrator.Engine,
	stager orchestrator.SecretStager,
	pool *orchestrator.WorkerPool,
) *Server {
	return &Server{
		logger: logger,
		cfg:    cfg,
		store:  store,
		engine: engine,
		stager: stager,
		pool:   pool,
	}
}

// Routes constructs the mux router with signature verification middleware.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthCheck())

	webhookHandler := http.HandlerFunc(s.handleGitHubWebhook())
	mux.Handle("POST /webhooks/github", ValidateGitHubSignature(s.cfg.WebhookSecret)(webhookHandler))

	return mux
}

func (s *Server) respond(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := fmt.Fprint(w, body); err != nil {
		s.logger.Error("Failed to write HTTP response", "error", err)
	}
}

func (s *Server) handleHealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, http.StatusOK, `{"status":"healthy"}`)
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
			s.respond(w, http.StatusOK, `{"status":"pong"}`)
			return
		}

		if event != vcs.EventPullRequest {
			s.logger.Debug("Ignoring non-PR webhook event", "event", event)
			s.respond(w, http.StatusAccepted, `{"status":"ignored"}`)
			return
		}

		var payload vcs.PullRequestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			s.logger.Error("Malformed JSON webhook payload", "error", err)
			http.Error(w, "invalid JSON payload", http.StatusBadRequest)
			return
		}

		envID := fmt.Sprintf("pr-%d", payload.Number)

		switch payload.Action {
		case vcs.ActionOpened, vcs.ActionReopened, vcs.ActionSynchronize:
			s.logger.Info("Queueing environment deployment",
				"environment_id", envID,
				"pr_number", payload.Number,
				"action", payload.Action,
				"commit_sha", payload.PullRequest.Head.SHA,
			)

			s.pool.Submit(orchestrator.Job{
				EnvID:    envID,
				PRNumber: payload.Number,
				CloneURL: payload.Repository.CloneURL,
				Commit:   payload.PullRequest.Head.SHA,
			})

			s.respond(w, http.StatusAccepted, fmt.Sprintf(`{"status":"queued","environment_id":"%s"}`, envID))

		case vcs.ActionClosed:
			s.logger.Info("Triggering environment teardown",
				"environment_id", envID,
				"pr_number", payload.Number,
			)

			if err := orchestrator.Teardown(r.Context(), s.engine, s.stager, envID); err != nil {
				s.logger.Error("Failed to destroy environment on PR close", "environment_id", envID, "error", err)
			}
			if err := s.store.DeleteEnvironment(r.Context(), envID); err != nil {
				s.logger.Error("Failed to delete store record on PR close", "environment_id", envID, "error", err)
			}

			s.respond(w, http.StatusOK, fmt.Sprintf(`{"status":"terminated","environment_id":"%s"}`, envID))

		default:
			s.logger.Debug("Unsupported PR action ignored", "action", payload.Action)
			s.respond(w, http.StatusAccepted, `{"status":"action_ignored"}`)
		}
	}
}
