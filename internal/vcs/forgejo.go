package vcs

// The Forgejo driver (V1.2 spec 3.1): Forgejo and Gitea through REST API v1.
// previewd holds one access token, read from a systemd credential into
// memory, sent as "Authorization: token <token>" to the one configured host
// and nowhere else: no redirect is followed, so the header cannot be carried
// to another host.
//
// Forgejo is shaped like GitHub: owner/repo names, pull requests numbered in
// their repository, reviews bound to the commit they were given on, the
// collaborator permission of an account. The driver therefore serves the
// GHES deploy gate (orchestrator.GHESAuthorizer) as it is: PullRequest,
// Reviews and Permission read Forgejo as Client reads GHES, and the trust
// rule is vcs.Trusted.
//
// The token's account needs:
//   - read access to each served repository, to read pull requests, reviews
//     and archives (token scope read:repository);
//   - Administrator access to it, because Forgejo serves the permission of
//     another account to repository administrators only, and trust and
//     approvals are judged on it;
//   - for the developer feedback: write:repository (commit status),
//     write:issue (the sticky comment) and read:user (the account the token
//     acts as, whose comment is the sticky one). Without them the writes are
//     refused and logged; the deploy is not affected.
//
// Like the GHES and GitLab clients: REST over net/http only (no SDK), HTTPS
// only, the site CA when one is configured, no proxy from the environment,
// every reply bounded and every call timed out. A reply that cannot be read
// completely and consistently is an error, never a default.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// forgejoAPIPrefix is the REST root of Forgejo and Gitea.
	forgejoAPIPrefix = "/api/v1"
	// ForgejoSignatureHeader and GiteaSignatureHeader carry the 64 lowercase
	// hex digits of HMAC-SHA256(secret, body), without GitHub's "sha256="
	// prefix. Forgejo sends both; Gitea the second.
	ForgejoSignatureHeader = "X-Forgejo-Signature"
	GiteaSignatureHeader   = "X-Gitea-Signature"

	// Review types of a Forgejo review event (review.type in the body).
	forgejoReviewApproved = "pull_request_review_approved"
	forgejoReviewRejected = "pull_request_review_rejected"

	// forgejoReviewsPerPage is the page size asked for. Forgejo serves at
	// most its MAX_RESPONSE_ITEMS (50 by default) whatever is asked, so the
	// pages are read until one comes back empty, never until one comes back
	// short; maxForgejoReviewPages bounds that.
	forgejoReviewsPerPage = 50
	maxForgejoReviewPages = 20
)

// ForgejoConfig configures a Forgejo driver. Token is the access token (held
// in memory only); CAPEM the site CA bundle, nil for the system roots.
type ForgejoConfig struct {
	BaseURL string // PREVIEWD_FORGEJO_URL: the https scheme, a host and an optional port
	Token   []byte
	CAPEM   []byte
	Logger  *slog.Logger
}

// Forgejo reads Forgejo (or Gitea) as the holder of an access token.
type Forgejo struct {
	api    string
	token  string
	http   *http.Client
	dl     *http.Client
	logger *slog.Logger
}

// NewForgejo validates the configuration. It makes no call.
func NewForgejo(cfg ForgejoConfig) (*Forgejo, error) {
	base, err := validate.ForgejoURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if !validToken(string(cfg.Token)) {
		return nil, errors.New("forgejo token: want 1 to 255 printable characters without space")
	}
	transport, err := newTransport(cfg.CAPEM, "Forgejo")
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Forgejo{
		api:   base + forgejoAPIPrefix,
		token: string(cfg.Token),
		http:  &http.Client{Timeout: callTimeout, Transport: transport, CheckRedirect: noRedirect},
		// Archive downloads last longer than one call: bounded by the
		// fetch's context instead, still without proxy or redirect.
		dl:     &http.Client{Transport: transport, CheckRedirect: noRedirect},
		logger: logger,
	}, nil
}

// Name implements Provider.
func (f *Forgejo) Name() string { return ProviderForgejo }

// VerifyWebhook implements Provider: the HMAC-SHA256 of the body, as 64
// lowercase hex digits in X-Forgejo-Signature or X-Gitea-Signature. Each
// header appears at most once, at least one appears, and every one that
// appears must match: a request whose two headers disagree is refused,
// whichever one is right. The digests are compared with
// subtle.ConstantTimeCompare. An empty secret refuses everything.
func (f *Forgejo) VerifyWebhook(req *http.Request, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: %w", validate.ErrSignature, errNoSecret)
	}
	var sigs [][]byte
	for _, h := range []string{ForgejoSignatureHeader, GiteaSignatureHeader} {
		values := req.Header.Values(h)
		switch {
		case len(values) > 1:
			return nil, fmt.Errorf("%w: more than one %s header", validate.ErrSignature, h)
		case len(values) == 0:
			continue
		}
		sig, ok := forgejoDigest(values[0])
		if !ok {
			return nil, fmt.Errorf("%w: malformed %s header", validate.ErrSignature, h)
		}
		sigs = append(sigs, sig)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("%w: no %s or %s header", validate.ErrSignature, ForgejoSignatureHeader, GiteaSignatureHeader)
	}
	body, err := readWebhookBody(req)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	want := mac.Sum(nil)
	for _, sig := range sigs {
		if subtle.ConstantTimeCompare(sig, want) != 1 {
			return nil, fmt.Errorf("%w: signature mismatch", validate.ErrSignature)
		}
	}
	restoreBody(req, body)
	return body, nil
}

// forgejoDigest decodes a signature header: exactly 64 lowercase hex digits.
func forgejoDigest(s string) ([]byte, bool) {
	if len(s) != hex.EncodedLen(sha256.Size) || strings.ToLower(s) != s {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// fjAccountWire is a Forgejo user object.
type fjAccountWire struct {
	ID    *int64  `json:"id"`
	Login *string `json:"login"`
}

func (a *fjAccountWire) account(role string) (Account, error) {
	if a == nil || a.ID == nil || a.Login == nil {
		return Account{}, fmt.Errorf("%s: missing required field", role)
	}
	if err := validate.ForgejoUsername(*a.Login); err != nil || *a.ID <= 0 {
		return Account{}, fmt.Errorf("%s: invalid account %s (id %d)", role, validate.Quote(*a.Login), *a.ID)
	}
	return Account{Login: *a.Login, ID: *a.ID}, nil
}

type fjRepoWire struct {
	FullName *string `json:"full_name"`
	CloneURL *string `json:"clone_url"`
}

// pullRequestHookWire is the part of a Forgejo pull request hook used, for
// pull_request and for review deliveries (both carry a PullRequestPayload).
type pullRequestHookWire struct {
	Action      *string `json:"action"`
	Number      *uint32 `json:"number"`
	PullRequest *struct {
		Number *uint32 `json:"number"`
		Head   *struct {
			Ref  *string     `json:"ref"`
			SHA  *string     `json:"sha"`
			Repo *fjRepoWire `json:"repo"`
		} `json:"head"`
		User      *fjAccountWire `json:"user"`
		UpdatedAt *string        `json:"updated_at"`
	} `json:"pull_request"`
	Repository *fjRepoWire    `json:"repository"`
	Sender     *fjAccountWire `json:"sender"`
	Review     *struct {
		Type *string `json:"type"`
	} `json:"review"`
}

// ParseEvent implements Provider for a pull_request or a review delivery.
// The mapping to previewd's actions: opened, reopened, closed (a merge is a
// close); synchronized (Forgejo) and synchronize (Gitea before 1.17) are a
// push. A review ("reviewed") approving is ActionApproved, one requesting
// changes ActionChangesRequested; a comment review builds nothing. Labels
// carry no authority on Forgejo (approvals do, and Forgejo's label events do
// not say which label changed): labeled, unlabeled, label_updated and
// label_cleared are recognized and ignored, as is every other action. The
// head, the author and the update time come from the signed body.
func (f *Forgejo) ParseEvent(payload []byte) (*Event, error) {
	reject := func(format string, args ...any) (*Event, error) {
		return nil, fmt.Errorf("%w: %s", validate.ErrPayload, fmt.Sprintf(format, args...))
	}
	if len(payload) > validate.MaxPayloadBytes {
		return reject("body exceeds %d bytes", validate.MaxPayloadBytes)
	}
	var w pullRequestHookWire
	if err := json.Unmarshal(payload, &w); err != nil {
		return reject("invalid JSON: %v", err)
	}
	if w.Action == nil {
		return reject("missing required field")
	}
	ev, err := w.event()
	if err != nil {
		return reject("%v", err)
	}
	if ev.Action, err = fjAction(*w.Action, w.Review); err != nil {
		return nil, err
	}
	return ev, nil
}

// event validates the fields every action needs.
func (w *pullRequestHookWire) event() (*Event, error) {
	pr, repo := w.PullRequest, w.Repository
	if w.Number == nil || pr == nil || pr.Number == nil || pr.Head == nil || pr.Head.Ref == nil || pr.Head.SHA == nil ||
		pr.UpdatedAt == nil || (pr.Head.Repo != nil && pr.Head.Repo.FullName == nil) ||
		repo == nil || repo.FullName == nil || repo.CloneURL == nil {
		return nil, errors.New("missing required field")
	}
	author, err := pr.User.account("author")
	if err != nil {
		return nil, err
	}
	sender, err := w.Sender.account("sender")
	if err != nil {
		return nil, err
	}
	ev := &Event{
		ProjectID: *repo.FullName, Project: *repo.FullName, IID: *w.Number,
		HeadRef: *pr.Head.Ref, HeadSHA: *pr.Head.SHA, CloneURL: *repo.CloneURL,
		Author: author, Sender: sender,
	}
	switch {
	case ev.IID == 0:
		return nil, errors.New("pull request number must be positive")
	case *pr.Number != ev.IID:
		return nil, fmt.Errorf("the pull request is #%d, the event #%d", *pr.Number, ev.IID)
	}
	if pr.Head.Repo != nil {
		ev.HeadProject = *pr.Head.Repo.FullName
		if err := validate.ForgejoRepoFullName(ev.HeadProject); err != nil {
			return nil, fmt.Errorf("head %w", err)
		}
	}
	if ev.UpdatedAt, err = validate.Timestamp(*pr.UpdatedAt); err != nil {
		return nil, fmt.Errorf("pull request updated_at: %w", err)
	}
	for _, check := range []error{
		validate.ForgejoRepoFullName(ev.Project), validate.GitRef(ev.HeadRef), validate.CommitSHA(ev.HeadSHA), validate.CloneURL(ev.CloneURL),
	} {
		if check != nil {
			return nil, check
		}
	}
	return ev, nil
}

// fjAction maps a Forgejo pull request action to previewd's.
func fjAction(action string, review *struct {
	Type *string `json:"type"`
}) (string, error) {
	switch action {
	case "opened":
		return ActionOpened, nil
	case "reopened":
		return ActionReopened, nil
	case "synchronized", "synchronize":
		return ActionSynchronize, nil
	case "closed":
		return ActionClosed, nil
	case "reviewed":
		if review == nil || review.Type == nil {
			return "", fmt.Errorf("%w: review without its type", validate.ErrPayload)
		}
		switch *review.Type {
		case forgejoReviewApproved:
			return ActionApproved, nil
		case forgejoReviewRejected:
			return ActionChangesRequested, nil
		}
		return "", fmt.Errorf("%w: review %s", validate.ErrIgnoredAction, validate.Quote(*review.Type))
	case "labeled", "unlabeled", "label_updated", "label_cleared":
		return "", fmt.Errorf("%w: label action %s: labels carry no authority on Forgejo", validate.ErrIgnoredAction, validate.Quote(action))
	}
	return "", fmt.Errorf("%w: pull request action %s", validate.ErrIgnoredAction, validate.Quote(action))
}

// forgejoRepoPath validates owner/repo and returns its URL path form.
func forgejoRepoPath(repo string) (string, error) {
	if err := validate.ForgejoRepoFullName(repo); err != nil {
		return "", err
	}
	owner, name, _ := strings.Cut(repo, "/")
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}

// do sends one request authenticated by the token; a body is JSON. The
// caller closes the reply (decodeReply does).
func (f *Forgejo) do(ctx context.Context, client *http.Client, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.api+path, rd)
	if err != nil {
		return nil, fmt.Errorf("%s %s: build request: %w", method, path, err)
	}
	req.Header.Set("Authorization", "token "+f.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	return resp, nil
}

// call performs one request, requires status want and decodes at most limit
// bytes of JSON into v. A larger reply is an error, never truncated.
func (f *Forgejo) call(ctx context.Context, method, path string, body []byte, want int, limit int64, v any) error {
	resp, err := f.do(ctx, f.http, method, path, body)
	if err != nil {
		return err
	}
	return decodeReply(resp, method, path, want, limit, v)
}

func (f *Forgejo) get(ctx context.Context, path string, limit int64, v any) error {
	return f.call(ctx, http.MethodGet, path, nil, http.StatusOK, limit, v)
}

// fjPullReply is the part of GET /repos/{o}/{r}/pulls/{n} used.
type fjPullReply struct {
	Number *int64  `json:"number"`
	State  *string `json:"state"`
	Head   *struct {
		SHA  *string     `json:"sha"`
		Repo *fjRepoWire `json:"repo"`
	} `json:"head"`
	Base *struct {
		Repo *fjRepoWire `json:"repo"`
	} `json:"base"`
	User   *fjAccountWire `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// PullRequest reads pull request number of repo, and its author's
// permission on repo when the head lives there, as Client.PullRequest reads
// GHES: the deploy gate's truth. Any reply that is not complete and
// consistent is an error.
func (f *Forgejo) PullRequest(ctx context.Context, repo string, number uint32) (PRState, error) {
	path, err := forgejoRepoPath(repo)
	if err != nil {
		return PRState{}, err
	}
	if number == 0 {
		return PRState{}, errors.New("pull request number must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var pr fjPullReply
	if err := f.get(ctx, path+"/pulls/"+strconv.FormatUint(uint64(number), 10), maxPRReplyBytes, &pr); err != nil {
		return PRState{}, fmt.Errorf("read %s#%d: %w", repo, number, err)
	}
	st, err := f.state(pr, repo, number)
	if err != nil {
		return PRState{}, fmt.Errorf("read %s#%d: %w", repo, number, err)
	}
	if st.HeadRepo != repo {
		return st, nil // a fork, or a deleted head: never trusted, no permission read
	}
	if st.OpenerPermission, err = f.permission(ctx, path, st.Opener); err != nil {
		return PRState{}, fmt.Errorf("read %s#%d: %w", repo, number, err)
	}
	return st, nil
}

// state validates a pull request reply; the opener's permission is read by
// PullRequest.
func (f *Forgejo) state(pr fjPullReply, repo string, number uint32) (PRState, error) {
	if pr.Number == nil || pr.State == nil || pr.Head == nil || pr.Head.SHA == nil ||
		pr.Base == nil || pr.Base.Repo == nil || pr.Base.Repo.FullName == nil {
		return PRState{}, errors.New("the reply is incomplete")
	}
	if *pr.Number != int64(number) || !strings.EqualFold(*pr.Base.Repo.FullName, repo) {
		return PRState{}, fmt.Errorf("the reply is for %s#%d", validate.Quote(*pr.Base.Repo.FullName), *pr.Number)
	}
	var st PRState
	switch *pr.State {
	case "open":
		st.Open = true
	case "closed":
	default:
		return PRState{}, fmt.Errorf("unknown pull request state %s", validate.Quote(*pr.State))
	}
	if err := validate.CommitSHA(*pr.Head.SHA); err != nil {
		return PRState{}, fmt.Errorf("head: %w", err)
	}
	st.HeadSHA = *pr.Head.SHA
	if pr.Head.Repo != nil {
		if pr.Head.Repo.FullName == nil {
			return PRState{}, errors.New("head repository without its name")
		}
		if err := validate.ForgejoRepoFullName(*pr.Head.Repo.FullName); err != nil {
			return PRState{}, fmt.Errorf("head repository: %w", err)
		}
		st.HeadRepo = *pr.Head.Repo.FullName
	}
	opener, err := pr.User.account("author")
	if err != nil {
		return PRState{}, err
	}
	st.Opener = opener
	// Labels carry no authority on Forgejo: a name that is not valid is left
	// out, not an error.
	for _, l := range pr.Labels {
		if err := validate.LabelName(l.Name); err != nil {
			f.logger.Debug("Ignoring a Forgejo label", "label", validate.Quote(l.Name))
			continue
		}
		st.Labels = append(st.Labels, l.Name)
	}
	return st, nil
}

// Permission reads who's permission on repo, in GitHub's vocabulary (admin,
// write, read or none: Forgejo's owner is admin). It is read by who.Login and
// must come back for who.ID: otherwise the error wraps ErrAccountMismatch.
func (f *Forgejo) Permission(ctx context.Context, repo string, who Account) (string, error) {
	path, err := forgejoRepoPath(repo)
	if err != nil {
		return "", err
	}
	if err := validate.ForgejoUsername(who.Login); err != nil || who.ID < 1 {
		return "", fmt.Errorf("permission of %s (id %d): invalid account", validate.Quote(who.Login), who.ID)
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	level, err := f.permission(ctx, path, who)
	if err != nil {
		return "", fmt.Errorf("read the permission of %s#%d on %s: %w", who.Login, who.ID, repo, err)
	}
	return level, nil
}

func (f *Forgejo) permission(ctx context.Context, path string, who Account) (string, error) {
	var perm struct {
		Permission *string        `json:"permission"`
		User       *fjAccountWire `json:"user"`
	}
	if err := f.get(ctx, path+"/collaborators/"+url.PathEscape(who.Login)+"/permission", maxReplyBytes, &perm); err != nil {
		return "", err
	}
	if perm.User == nil || perm.User.ID == nil || *perm.User.ID != who.ID {
		return "", fmt.Errorf("permission reply is not about account %d (%s): %w", who.ID, who.Login, ErrAccountMismatch)
	}
	if perm.Permission == nil {
		return "", errors.New("permission reply names no permission")
	}
	switch *perm.Permission {
	case "owner", "admin":
		return "admin", nil
	case "write", "read", "none":
		return *perm.Permission, nil
	}
	return "", fmt.Errorf("unknown permission %s", validate.Quote(*perm.Permission))
}

// fjReviewReply is one review of GET /repos/{o}/{r}/pulls/{n}/reviews.
type fjReviewReply struct {
	ID          *int64         `json:"id"`
	User        *fjAccountWire `json:"user"`
	State       *string        `json:"state"`
	CommitID    *string        `json:"commit_id"`
	Dismissed   bool           `json:"dismissed"`
	SubmittedAt *string        `json:"submitted_at"`
}

// Reviews reads the verdicts given on pull request number of repo, in the
// order they were given (by review ID): approvals and change requests, as
// GHES names them, a dismissed one as DISMISSED. Comments, pending reviews
// and review requests decide nothing and are left out, as is a review by an
// account that cannot be identified (a deleted account, a name the audit
// trail cannot keep: it cannot be a PREVIEWD_APPROVERS account). A verdict
// that cannot be read completely is an error, never skipped: skipping a
// change request would let the approval before it stand. More than
// maxForgejoReviewPages pages is an error, never a partial list.
func (f *Forgejo) Reviews(ctx context.Context, repo string, number uint32) ([]ReviewState, error) {
	path, err := forgejoRepoPath(repo)
	if err != nil {
		return nil, err
	}
	if number == 0 {
		return nil, errors.New("pull request number must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	var out []ReviewState
	seen := map[int64]bool{}
	for page := 1; ; page++ {
		if page > maxForgejoReviewPages {
			return nil, fmt.Errorf("read the reviews of %s#%d: more than %d pages: refusing a partial list", repo, number, maxForgejoReviewPages)
		}
		var batch []fjReviewReply
		q := url.Values{"limit": {strconv.Itoa(forgejoReviewsPerPage)}, "page": {strconv.Itoa(page)}}
		if err := f.get(ctx, fmt.Sprintf("%s/pulls/%d/reviews?%s", path, number, q.Encode()), maxReviewBytes, &batch); err != nil {
			return nil, fmt.Errorf("read the reviews of %s#%d: %w", repo, number, err)
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			rs, keep, err := f.review(r)
			if err != nil {
				return nil, fmt.Errorf("read the reviews of %s#%d: %w", repo, number, err)
			}
			if seen[rs.ID] {
				return nil, fmt.Errorf("read the reviews of %s#%d: review %d listed twice", repo, number, rs.ID)
			}
			seen[rs.ID] = true
			if keep {
				out = append(out, rs)
			}
		}
	}
	slices.SortFunc(out, func(a, b ReviewState) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// review validates one review; keep is false for one that decides nothing.
func (f *Forgejo) review(r fjReviewReply) (rs ReviewState, keep bool, err error) {
	if r.ID == nil || *r.ID < 1 || r.State == nil {
		return ReviewState{}, false, errors.New("a review without its id or state")
	}
	rs.ID = *r.ID
	switch *r.State {
	case "APPROVED":
		rs.State = "APPROVED"
	case "REQUEST_CHANGES":
		rs.State = "CHANGES_REQUESTED"
	case "COMMENT", "PENDING", "REQUEST_REVIEW":
		return rs, false, nil
	default:
		return ReviewState{}, false, fmt.Errorf("review %d: unknown state %s", rs.ID, validate.Quote(*r.State))
	}
	if r.Dismissed {
		rs.State = "DISMISSED"
	}
	if rs.User, err = r.User.account("reviewer"); err != nil {
		f.logger.Debug("Ignoring the review of an account that cannot be identified", "review_id", rs.ID, "error", err)
		return rs, false, nil
	}
	if r.CommitID == nil || validate.CommitSHA(*r.CommitID) != nil {
		return ReviewState{}, false, fmt.Errorf("review %d: invalid commit", rs.ID)
	}
	rs.CommitID = *r.CommitID
	if r.SubmittedAt != nil && *r.SubmittedAt != "" {
		if rs.SubmittedAt, err = validate.Timestamp(*r.SubmittedAt); err != nil {
			return ReviewState{}, false, fmt.Errorf("review %d: %w", rs.ID, err)
		}
	}
	return rs, true, nil
}

// GetMRState implements Provider: projectID is owner/repo, mrIID the pull
// request number.
func (f *Forgejo) GetMRState(ctx context.Context, projectID, mrIID string) (*MRState, error) {
	number, err := validate.MergeRequestIID(mrIID)
	if err != nil {
		return nil, err
	}
	pr, err := f.PullRequest(ctx, projectID, number)
	if err != nil {
		return nil, err
	}
	return &MRState{
		Open: pr.Open, HeadSHA: pr.HeadSHA, HeadProject: pr.HeadRepo, Author: pr.Opener,
		Trusted: Trusted(pr, projectID), Labels: pr.Labels,
	}, nil
}

// GetApprovals implements Provider: the approvals still standing in the
// request's reviews, each on the commit it was given on.
func (f *Forgejo) GetApprovals(ctx context.Context, projectID, mrIID string) ([]Approval, error) {
	number, err := validate.MergeRequestIID(mrIID)
	if err != nil {
		return nil, err
	}
	reviews, err := f.Reviews(ctx, projectID, number)
	if err != nil {
		return nil, err
	}
	return standingApprovals(reviews), nil
}

// SetCommitStatus implements Provider: POST /repos/{o}/{r}/statuses/{sha} in
// the context "previewd". Forgejo names the three states as previewd does.
func (f *Forgejo) SetCommitStatus(ctx context.Context, projectID, commitSHA, state, targetURL, description string) error {
	if err := checkStatus(commitSHA, state, targetURL, description); err != nil {
		return err
	}
	path, err := forgejoRepoPath(projectID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		State       string `json:"state"`
		TargetURL   string `json:"target_url,omitempty"`
		Description string `json:"description"`
		Context     string `json:"context"`
	}{state, targetURL, description, statusContext})
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if err := f.call(ctx, http.MethodPost, path+"/statuses/"+commitSHA, body, http.StatusCreated, maxReplyBytes, nil); err != nil {
		return fmt.Errorf("set %s status of %s@%s: %w", state, projectID, commitSHA, err)
	}
	return nil
}

// fjComment is the part of a comment of GET .../issues/{n}/comments used.
type fjComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User *struct {
		ID int64 `json:"id"`
	} `json:"user"`
}

// PostComment implements Provider: the sticky comment of the pull request,
// an issue comment of its number. The comment is the one the token's own
// account wrote (GET /user) that starts with the marker; a comment of anyone
// else is never taken for it, and never edited. Forgejo serves the comments
// of a thread in one reply, bounded by maxCommentsReply: a longer thread is
// an error, never a second comment.
func (f *Forgejo) PostComment(ctx context.Context, projectID, mrIID, body string) error {
	if err := checkComment(body); err != nil {
		return err
	}
	number, err := validate.MergeRequestIID(mrIID)
	if err != nil {
		return err
	}
	path, err := forgejoRepoPath(projectID)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Body string `json:"body"`
	}{body})
	if err != nil {
		return fmt.Errorf("encode comment: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if err := f.postComment(ctx, path, number, body, payload); err != nil {
		return fmt.Errorf("post comment on %s#%d: %w", projectID, number, err)
	}
	return nil
}

func (f *Forgejo) postComment(ctx context.Context, path string, number uint32, body string, payload []byte) error {
	var me struct {
		ID int64 `json:"id"`
	}
	if err := f.get(ctx, "/user", maxReplyBytes, &me); err != nil {
		return err
	}
	if me.ID < 1 {
		return errors.New("the token's account is not named: no comment is its own")
	}
	comments := path + "/issues/" + strconv.FormatUint(uint64(number), 10) + "/comments"
	var thread []fjComment
	if err := f.get(ctx, comments, maxCommentsReply, &thread); err != nil {
		return err
	}
	for _, c := range thread {
		if c.ID < 1 || c.User == nil || c.User.ID != me.ID || !strings.HasPrefix(c.Body, CommentMarker) {
			continue
		}
		if strings.ReplaceAll(c.Body, "\r\n", "\n") == body {
			return nil // unchanged: nothing to write
		}
		return f.call(ctx, http.MethodPatch, path+"/issues/comments/"+strconv.FormatInt(c.ID, 10), payload, http.StatusOK, maxReplyBytes, nil)
	}
	return f.call(ctx, http.MethodPost, comments, payload, http.StatusCreated, maxReplyBytes, nil)
}

// FetchTarball implements Provider: it streams
// GET /repos/{o}/{r}/archive/{commit}.tar.gz with the token and extracts it
// into destDir, which it creates, through extractTarball (an os.Root, the
// bounds of the GHES tarball). Forgejo builds the archive with git archive
// of the commit, whose pax global header names it: an archive of any other
// commit is refused. Forgejo serves the archive itself; a redirect (an
// object store configured to serve archives directly) is refused, so the
// token cannot be carried to another host. maxBytes bounds the compressed
// archive and the bytes it extracts; the whole fetch is bounded by
// fetchTimeout.
func (f *Forgejo) FetchTarball(ctx context.Context, projectID, commitSHA, destDir string, maxBytes int64) error {
	path, err := forgejoRepoPath(projectID)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", validate.Quote(projectID), err)
	}
	if err := validate.CommitSHA(commitSHA); err != nil {
		return fmt.Errorf("fetch %s: %w", projectID, err)
	}
	if maxBytes <= 0 {
		return fmt.Errorf("fetch %s: size cap must be positive, got %d", projectID, maxBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	resp, err := f.do(ctx, f.dl, http.MethodGet, path+"/archive/"+commitSHA+".tar.gz", nil)
	if err != nil {
		return fmt.Errorf("fetch %s@%s: %w", projectID, commitSHA, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("fetch %s@%s: download the archive: HTTP %d", projectID, commitSHA, resp.StatusCode)
	case resp.ContentLength > maxBytes:
		return fmt.Errorf("fetch %s@%s: download the archive: %d bytes, above the %d-byte cap",
			projectID, commitSHA, resp.ContentLength, maxBytes)
	}
	body := &cappedReader{r: resp.Body, left: maxBytes}
	if err := extractTarball(body, commitSHA, destDir, maxBytes, maxTarEntries); err != nil {
		return fmt.Errorf("fetch %s@%s: %w", projectID, commitSHA, err)
	}
	// The rest of the stream (gzip trailer, padding) is read to the cap.
	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("fetch %s@%s: download the archive: %w", projectID, commitSHA, err)
	}
	return nil
}

// ForgejoFetcher fetches the source of a commit for the reconciler: the
// repository's archive, never git with the hook's clone URL.
type ForgejoFetcher struct {
	forgejo  *Forgejo
	maxBytes int64
}

// NewForgejoFetcher returns the fetcher of a Forgejo deployment. maxBytes
// (PREVIEWD_MAX_BUILD_CONTEXT_MIB) bounds both the compressed archive and the
// bytes it extracts.
func NewForgejoFetcher(f *Forgejo, maxBytes int64) (*ForgejoFetcher, error) {
	switch {
	case f == nil:
		return nil, errors.New("source fetch: no Forgejo driver")
	case maxBytes <= 0:
		return nil, fmt.Errorf("source fetch: size cap must be positive, got %d", maxBytes)
	}
	return &ForgejoFetcher{forgejo: f, maxBytes: maxBytes}, nil
}

// Fetch writes the tree of commitSHA of repo into destDir, which must not
// exist yet. It has the shape of orchestrator.FetchFunc.
func (f *ForgejoFetcher) Fetch(ctx context.Context, repo, _, commitSHA, destDir string) error {
	return f.forgejo.FetchTarball(ctx, repo, commitSHA, destDir, f.maxBytes)
}
