package api

// The CI trigger API (V1.2 spec 3.4), for the companion GitHub Action and
// GitLab CI component (deployments/ci/): a pipeline asks previewd to deploy
// a pull or merge request and polls until its preview is up.
//
//	POST /api/v1/trigger          {"repository": "owner/repo", "pull_request": 7}
//	GET  /api/v1/status/{envid}
//
// A trigger is a request, not an authority. It names a project and a number,
// nothing else: the branch, the commit, the head project, the author and the
// clone URL are read from the forge in the same step, and the deploy it
// queues is classified by the deploy gate like a webhook's, from the forge
// again (trusted, or an untrusted head that runs only on an approver's
// approval of its exact commit). The trigger token therefore lets a caller
// ask for what the forge already says, sooner; it never approves, never
// names a commit, and a head already queued or running is not rebuilt.
//
// Both routes are off unless PREVIEWD_TRIGGER_API=1. Every request is rate
// limited before it is authenticated (a token guessed at the rate the
// bucket allows is guessed never), then authenticated by a bearer token from
// a systemd credential, compared in constant time.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	// maxTriggerBody bounds a trigger request.
	maxTriggerBody = 4 << 10
	// Rate limits: a pipeline triggers once and polls every few seconds.
	triggerBurst, triggerEvery = 10, 6 * time.Second
	statusBurst, statusEvery   = 120, 500 * time.Millisecond
)

// Heads is the forge truth a trigger is built from: the request's head now
// (vcs.Client, vcs.GitLab, vcs.Forgejo).
type Heads interface {
	PullRequestHead(ctx context.Context, project string, number uint32) (vcs.Head, error)
}

// Environments is what the queue knows of an environment (store.Store).
type Environments interface {
	Environment(ctx context.Context, envID string) (store.EnvironmentStatus, bool, error)
}

// trigger is the configuration of the trigger API: the digest of its token
// (the token itself is not kept), the forge and store reads, and the rate
// limits of its two routes.
type trigger struct {
	digest  [sha256.Size]byte
	heads   Heads
	envs    Environments
	deploys *bucket
	reads   *bucket
}

// WithTrigger enables the trigger API (PREVIEWD_TRIGGER_API=1) under token,
// the bearer token read from its systemd credential: at least 32 printable
// characters (secrets.TriggerToken). NewServer refuses a shorter one, or a
// missing forge or store read. Only the token's digest is kept, computed
// here: the caller can clear token as soon as WithTrigger returns.
func WithTrigger(token []byte, heads Heads, envs Environments) Option {
	err := checkTriggerToken(token)
	if heads == nil || envs == nil {
		err = errors.Join(err, errors.New("trigger API: no forge or store to read"))
	}
	digest := sha256.Sum256(token)
	return func(s *Server) {
		s.triggerErr = err
		s.trigger = &trigger{
			digest: digest, heads: heads, envs: envs,
			deploys: newBucket(triggerBurst, triggerEvery), reads: newBucket(statusBurst, statusEvery),
		}
	}
}

func checkTriggerToken(token []byte) error {
	if len(token) < 32 || len(token) > 255 {
		return errors.New("trigger API: the token must be 32 to 255 characters")
	}
	for _, c := range token {
		if c <= ' ' || c > '~' {
			return errors.New("trigger API: the token must be printable ASCII without space")
		}
	}
	return nil
}

// bucket is a token bucket: burst requests at once, one more every refill.
// It starts full, at its first request.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	refill time.Duration
	last   time.Time
}

func newBucket(burst int, refill time.Duration) *bucket {
	return &bucket{tokens: float64(burst), burst: float64(burst), refill: refill}
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.last = now
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+float64(elapsed)/float64(b.refill))
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// guarded rate-limits by b, then requires the trigger token.
func (s *Server) guarded(b *bucket, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !b.take(s.now()) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		auth := r.Header.Values("Authorization")
		token, ok := "", len(auth) == 1
		if ok {
			token, ok = strings.CutPrefix(auth[0], "Bearer ")
		}
		got := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(got[:], s.trigger.digest[:]) != 1 {
			s.logger.Warn("Trigger API request refused: no valid token", "path", r.URL.Path)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// triggerReply is the answer of both routes.
type triggerReply struct {
	Status        string     `json:"status"`
	EnvironmentID string     `json:"environment_id,omitempty"`
	JobID         int64      `json:"job_id,omitempty"`
	State         string     `json:"state,omitempty"`
	JobStatus     string     `json:"job_status,omitempty"`
	CommitSHA     string     `json:"commit_sha,omitempty"`
	Failure       string     `json:"failure,omitempty"`
	PreviewURL    string     `json:"preview_url,omitempty"`
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
}

func (s *Server) answer(w http.ResponseWriter, status int, body triggerReply) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.Error("Failed to write HTTP response", "error", err)
	}
}

// previewURL is the URL of envID's preview.
func (s *Server) previewURL(envID string) string {
	return s.cfg.PreviewScheme + "://" + envID + "." + s.cfg.TraefikDomain
}

// projectValid is the project name grammar of the forge served.
func (s *Server) projectValid(project string) error {
	switch s.cfg.VCSProvider {
	case vcs.ProviderGitLab:
		return validate.GitLabProjectPath(project)
	case vcs.ProviderForgejo:
		return validate.ForgejoRepoFullName(project)
	}
	return validate.RepoFullName(project)
}

func (s *Server) handleTrigger() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxTriggerBody+1))
		switch {
		case err != nil:
			http.Error(w, "payload read failure", http.StatusBadRequest)
			return
		case len(body) > maxTriggerBody:
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		var req struct {
			Repository  string `json:"repository"`
			PullRequest uint32 `json:"pull_request"`
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || dec.More() || s.projectValid(req.Repository) != nil || req.PullRequest == 0 {
			http.Error(w, `want {"repository": <project>, "pull_request": <number>}`, http.StatusBadRequest)
			return
		}
		log := s.logger.With("origin", "trigger", "repository", req.Repository, "pr_number", req.PullRequest)

		ctx, cancel := context.WithTimeout(r.Context(), ghesTimeout)
		head, err := s.trigger.heads.PullRequestHead(ctx, req.Repository, req.PullRequest)
		cancel()
		if err != nil {
			log.Error("Trigger refused: the forge cannot be read", "error", err)
			s.answer(w, http.StatusBadGateway, triggerReply{Status: "error"})
			return
		}
		envID := envid.Generate(req.Repository, head.Ref, uint64(req.PullRequest))
		log = log.With("environment_id", envID, "commit_sha", head.SHA)
		if !head.Open {
			log.Info("Trigger ignored: the request is not open")
			s.answer(w, http.StatusConflict, triggerReply{Status: "closed", EnvironmentID: envID})
			return
		}

		sctx, scancel := storeContext(r)
		defer scancel()
		st, found, err := s.trigger.envs.Environment(sctx, envID)
		if err != nil {
			log.Error("Could not read the environment", "error", err)
			s.answer(w, http.StatusInternalServerError, triggerReply{Status: "error"})
			return
		}
		if found && intends(st.Latest, head.SHA) {
			// The head is already queued, awaiting approval or running: a
			// trigger never rebuilds it.
			s.answer(w, http.StatusOK, triggerReply{Status: "current", EnvironmentID: envID, JobID: st.Latest.ID,
				State: st.State(), JobStatus: string(st.Latest.Status), CommitSHA: head.SHA})
			return
		}

		d, err := s.triggerDelivery(req.Repository, req.PullRequest, envID, head, body)
		if err != nil {
			log.Error("Trigger refused", "error", err)
			s.answer(w, http.StatusInternalServerError, triggerReply{Status: "error"})
			return
		}
		verdict, jobID, err := s.queue.Enqueue(sctx, d)
		switch {
		case err != nil:
			log.Error("Could not record the trigger", "error", err)
			s.answer(w, http.StatusInternalServerError, triggerReply{Status: "error"})
		case verdict == store.VerdictAccepted:
			log.Info("Job queued by a trigger", "job_id", jobID, "delivery_id", d.ID)
			s.waker.Notify()
			s.answer(w, http.StatusAccepted, triggerReply{Status: "queued", EnvironmentID: envID, JobID: jobID, CommitSHA: head.SHA,
				PreviewURL: s.previewURL(envID)})
		default:
			log.Info("Trigger not queued", "verdict", string(verdict))
			s.answer(w, http.StatusOK, triggerReply{Status: string(verdict), EnvironmentID: envID})
		}
	}
}

// intends reports whether latest already deploys commit.
func intends(latest store.Job, commit string) bool {
	if latest.Type != store.JobDeploy || latest.Source.CommitSHA != commit {
		return false
	}
	switch latest.Status {
	case store.StatusQueued, store.StatusInProgress, store.StatusPendingApproval, store.StatusSuccess:
		return true
	}
	return false
}

// triggerDelivery is the deploy a trigger queues: the forge's head, ordered
// by the time this host received the request (validate.SeqAt), under a
// delivery ID and a payload digest of its own (a random nonce: two triggers
// are two intents, never replays of each other).
func (s *Server) triggerDelivery(repo string, number uint32, envID string, head vcs.Head, body []byte) (store.Delivery, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return store.Delivery{}, err
	}
	sum := sha256.Sum256(append(append([]byte{}, body...), nonce[:]...))
	opener := head.Author.Login
	if len(opener) > maxRecordedLogin {
		opener = "user-" + strconv.FormatInt(head.Author.ID, 10)
	}
	received := s.now()
	return store.Delivery{
		ID: "trigger-" + hex.EncodeToString(nonce[:]), PayloadSHA256: hex.EncodeToString(sum[:]), EnvID: envID,
		Type: store.JobDeploy, Seq: validate.SeqAt(received), ReceivedAt: received,
		Source: store.Source{Repo: repo, HeadRepo: head.HeadProject, PRNumber: int64(number), OpenerLogin: opener,
			OpenerID: head.Author.ID, CommitSHA: head.SHA, CloneURL: head.CloneURL},
	}, nil
}

func (s *Server) handleStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		envID := r.PathValue("envid")
		if !envid.Valid(envID) {
			http.Error(w, "invalid environment id", http.StatusBadRequest)
			return
		}
		ctx, cancel := storeContext(r)
		defer cancel()
		st, found, err := s.trigger.envs.Environment(ctx, envID)
		switch {
		case err != nil:
			s.logger.Error("Could not read the environment", "environment_id", envID, "error", err)
			s.answer(w, http.StatusInternalServerError, triggerReply{Status: "error"})
			return
		case !found:
			s.answer(w, http.StatusNotFound, triggerReply{Status: "unknown", EnvironmentID: envID})
			return
		}
		rep := triggerReply{
			Status: "ok", EnvironmentID: envID, JobID: st.Latest.ID, State: st.State(), JobStatus: string(st.Latest.Status),
			CommitSHA: st.Latest.Source.CommitSHA, Failure: string(st.Latest.Failure),
		}
		if st.Running() {
			rep.PreviewURL = s.previewURL(envID)
		}
		if !st.LastActive.IsZero() {
			at := st.LastActive
			rep.LastActiveAt = &at
		}
		s.answer(w, http.StatusOK, rep)
	}
}

// triggerRoutes mounts the trigger API on mux behind its own source filter
// (PREVIEWD_TRIGGER_ALLOWED_CIDRS: the CI runners, not the forge).
func (s *Server) triggerRoutes(mux *http.ServeMux, logger *slog.Logger) {
	if s.trigger == nil {
		return
	}
	source := SourceFilter(s.cfg.TriggerAllowedCIDRs, logger)
	mux.Handle("POST /api/v1/trigger", source(s.guarded(s.trigger.deploys, s.handleTrigger())))
	mux.Handle("GET /api/v1/status/{envid}", source(s.guarded(s.trigger.reads, s.handleStatus())))
}
