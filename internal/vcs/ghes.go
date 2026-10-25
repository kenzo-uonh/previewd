package vcs

// The GHES client (V1 spec C3, 3.5): previewd reads GitHub Enterprise Server
// as a GitHub App. It holds only the App's private key (a systemd
// credential, never a file on persistent disk). For each read it mints an
// installation token scoped to the one repository read, with read-only
// permissions, uses it, and revokes it before returning: no token outlives
// its use, none is stored, logged, or put in a URL.
//
// REST over net/http only (no SDK), HTTPS only, the site CA when one is
// configured, no proxy from the environment, no redirect (but the archive
// redirect of a source fetch, checked by hand: tarball.go), every reply
// bounded and every call timed out. A reply that cannot be read completely
// and consistently is an error, never a default.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenzo-uonh/previewd/internal/textutil"
	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// apiPrefix is the REST root of a GitHub Enterprise Server.
	apiPrefix        = "/api/v3"
	githubAPIVersion = "2022-11-28"
	userAgent        = "previewd"

	callTimeout   = 10 * time.Second
	readTimeout   = 30 * time.Second // one read: installation, token, the calls
	revokeTimeout = 5 * time.Second
	// jwtLifetime and jwtBackdate: GitHub accepts an App JWT valid for at
	// most 10 minutes; iat is set back a minute for clock drift.
	jwtLifetime = 9 * time.Minute
	jwtBackdate = time.Minute
	// maxTokenLifetime is the longest installation token accepted (GitHub
	// issues one-hour tokens).
	maxTokenLifetime = 2 * time.Hour

	maxReplyBytes   = 64 << 10
	maxPRReplyBytes = 1 << 20 // a PR body of 65536 characters, 4 bytes each, plus metadata
	maxReviewBytes  = 4 << 20 // one page of 100 reviews
	reviewsPerPage  = 100
	maxReviewPages  = 10
	maxTokenLen     = 255
	maxQuotedReply  = 256
)

// ErrAccountMismatch: a login read from GHES resolves to another account ID
// than the one asked for (a renamed account whose login was taken since).
var ErrAccountMismatch = errors.New("the login names another account")

// Account is a GitHub account: ID is the identity, Login the current name.
type Account struct {
	Login string
	ID    int64
}

// PRState is a pull request as GHES reports it at the time of the call: the
// truth an approval or a revocation is judged against (V1 spec 3.4).
// OpenerPermission is the opener's permission on the base repository, read
// with the same token; it is empty for a head outside the base repository,
// which cannot be trusted whatever the opener's permission.
type PRState struct {
	Open             bool
	HeadSHA          string
	HeadRepo         string // "" when the head repository (a fork) was deleted
	Opener           Account
	OpenerPermission string // admin, maintain, write, triage, read, none, or ""
	Labels           []string
}

// ReviewState is one review as GHES reports it now (D4 reads them).
type ReviewState struct {
	ID          int64
	User        Account
	State       string // APPROVED, CHANGES_REQUESTED, COMMENTED, DISMISSED, PENDING
	CommitID    string
	SubmittedAt time.Time // zero for a pending review
}

// WriteAccess reports whether a repository permission, as GHES names it,
// includes write: admin, maintain or write. Anything else, unknown names
// included, does not.
func WriteAccess(permission string) bool {
	switch permission {
	case "admin", "maintain", "write":
		return true
	}
	return false
}

// Trusted is the trust rule (V1 spec D4, D-V1-5): the head lives in the
// base repository and its opener has write access there. A deleted head
// repository is untrusted.
func Trusted(pr PRState, repo string) bool {
	return pr.HeadRepo != "" && pr.HeadRepo == repo && WriteAccess(pr.OpenerPermission)
}

// ClientConfig configures a Client. KeyPEM is the App's private key (PKCS#1
// as GitHub issues it, or PKCS#8); CAPEM the site CA bundle, nil for the
// system roots.
type ClientConfig struct {
	BaseURL string // PREVIEWD_GHES_URL: the https scheme, a host and an optional port
	AppID   int64
	KeyPEM  []byte
	CAPEM   []byte
	Logger  *slog.Logger
}

// Client reads GHES as the GitHub App.
type Client struct {
	api    string
	appID  int64
	key    *rsa.PrivateKey
	http   *http.Client
	dl     *http.Client
	logger *slog.Logger
	now    func() time.Time
}

// NewClient validates the configuration. It makes no call.
func NewClient(cfg ClientConfig) (*Client, error) {
	base, err := validate.GHESURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.AppID < 1 {
		return nil, errors.New("GitHub App ID must be positive")
	}
	key, err := parseAppKey(cfg.KeyPEM)
	if err != nil {
		return nil, err
	}
	transport, err := newTransport(cfg.CAPEM, "GHES")
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		api:   base + apiPrefix,
		appID: cfg.AppID,
		key:   key,
		http:  &http.Client{Timeout: callTimeout, Transport: transport, CheckRedirect: noRedirect},
		// Archive downloads (H2) last longer than one call: bounded by the
		// fetch's context instead, still without proxy or redirect.
		dl:     &http.Client{Transport: transport, CheckRedirect: noRedirect},
		logger: logger,
		now:    time.Now,
	}, nil
}

// noRedirect hands a redirect back to the caller: an API call follows none,
// and a source fetch checks the one it expects by hand.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newTransport is the transport of a forge client: TLS 1.2 or later against
// the site CA bundle caPEM (the system roots when nil), no proxy from the
// environment, bounded dial and handshake. what names the forge in errors.
func newTransport(caPEM []byte, what string) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != nil {
		var err error
		if tlsCfg.RootCAs, err = CertPool(caPEM); err != nil {
			return nil, fmt.Errorf("%s CA bundle: %w", what, err)
		}
	}
	return &http.Transport{
		Proxy:               nil, // never HTTP(S)_PROXY from the environment
		DialContext:         (&net.Dialer{Timeout: callTimeout}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: callTimeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
	}, nil
}

// CertPool returns a pool holding only the certificates of caPEM. Every PEM
// block must be a certificate: a bundle with a stray private key, a
// truncated block or trailing data is refused, never partly trusted.
func CertPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest, n := caPEM, 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("CA bundle holds a %q PEM block; only certificates are accepted", textutil.Truncate(block.Type, 32))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CA bundle certificate %d: %w", n+1, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, errors.New("CA bundle holds no PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("CA bundle has trailing data that is not a PEM block")
	}
	return pool, nil
}

func parseAppKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("GitHub App key: want exactly one PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return checkAppKey(k)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App key: not an RSA private key (PKCS#1 or PKCS#8)")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App key: not an RSA key")
	}
	return checkAppKey(rk)
}

func checkAppKey(k *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if k.N.BitLen() < 2048 {
		return nil, fmt.Errorf("GitHub App key: %d-bit RSA, want at least 2048", k.N.BitLen())
	}
	return k, nil
}

// jwt returns the App's JSON Web Token (RS256, RFC 7519), valid jwtLifetime.
func (c *Client) jwt() (string, error) {
	now := c.now()
	return signJWT(c.key, c.appID, now.Add(-jwtBackdate), now.Add(jwtLifetime))
}

func signJWT(key *rsa.PrivateKey, appID int64, iat, exp time.Time) (string, error) {
	enc := base64.RawURLEncoding
	claims, err := json.Marshal(struct {
		IAT int64 `json:"iat"`
		EXP int64 `json:"exp"`
		ISS int64 `json:"iss"`
	}{iat.Unix(), exp.Unix(), appID})
	if err != nil {
		return "", fmt.Errorf("encode JWT claims: %w", err)
	}
	signing := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// repoPath validates owner/repo and returns its URL path form.
func repoPath(repo string) (string, error) {
	if err := validate.RepoFullName(repo); err != nil {
		return "", err
	}
	owner, name, _ := strings.Cut(repo, "/")
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}

// get performs one GET with bearer, requires HTTP 200 and decodes at most
// limit bytes of JSON into v. A larger reply is an error, never truncated.
func (c *Client) get(ctx context.Context, bearer, path string, limit int64, v any) error {
	return c.call(ctx, http.MethodGet, bearer, path, nil, http.StatusOK, limit, v)
}

func (c *Client) call(ctx context.Context, method, bearer, path string, body []byte, want int, limit int64, v any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api+path, rd)
	if err != nil {
		return fmt.Errorf("%s %s: build request: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	return decodeReply(resp, method, path, want, limit, v)
}

// decodeReply closes resp, requires status want and decodes at most limit
// bytes of JSON into v (nothing when v is nil). A larger reply is an error,
// never truncated. An error document is quoted bounded: it never carries a
// token.
func decodeReply(resp *http.Response, method, path string, want int, limit int64, v any) error {
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if closeErr := resp.Body.Close(); readErr == nil {
		readErr = closeErr
	}
	switch {
	case readErr != nil:
		return fmt.Errorf("%s %s: read reply: %w", method, path, readErr)
	case resp.StatusCode != want:
		return fmt.Errorf("%s %s: HTTP %d: %q", method, path, resp.StatusCode,
			textutil.Truncate(strings.TrimSpace(string(raw)), maxQuotedReply))
	case int64(len(raw)) > limit:
		return fmt.Errorf("%s %s: reply exceeds %d bytes", method, path, limit)
	case v == nil:
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s %s: decode reply: %w", method, path, err)
	}
	return nil
}

// token is an installation token: its value never leaves this package.
type token struct {
	value   string
	repo    string
	expires time.Time
}

// tokenRequest is POST /app/installations/{id}/access_tokens.
type tokenRequest struct {
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
}

type tokenReply struct {
	Token        string            `json:"token"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Permissions  map[string]string `json:"permissions"`
	Repositories []struct {
		FullName string `json:"full_name"`
	} `json:"repositories"`
}

func validToken(t string) bool {
	if t == "" || len(t) > maxTokenLen {
		return false
	}
	for i := range len(t) {
		if c := t[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// mint returns an installation token for repo with the access perms name
// ("pull_requests" is read, "statuses:write" is write), and nothing else: a
// reply that grants another permission, another level, another repository,
// or a lifetime outside (0, 2 h] is revoked and refused.
func (c *Client) mint(ctx context.Context, repo string, perms ...string) (token, error) {
	path, err := repoPath(repo)
	if err != nil {
		return token{}, err
	}
	jwt, err := c.jwt()
	if err != nil {
		return token{}, err
	}
	var inst struct {
		ID int64 `json:"id"`
	}
	if err := c.get(ctx, jwt, path+"/installation", maxReplyBytes, &inst); err != nil {
		return token{}, fmt.Errorf("GitHub App installation on %s: %w", repo, err)
	}
	if inst.ID < 1 {
		return token{}, fmt.Errorf("GitHub App installation on %s: no installation ID", repo)
	}
	_, name, _ := strings.Cut(repo, "/")
	want := map[string]string{}
	for _, p := range perms {
		name, level, ok := strings.Cut(p, ":")
		if !ok {
			level = "read"
		}
		want[name] = level
	}
	body, err := json.Marshal(tokenRequest{Repositories: []string{name}, Permissions: want})
	if err != nil {
		return token{}, fmt.Errorf("encode token request: %w", err)
	}
	var reply tokenReply
	if err := c.call(ctx, http.MethodPost, jwt, "/app/installations/"+strconv.FormatInt(inst.ID, 10)+"/access_tokens",
		body, http.StatusCreated, maxReplyBytes, &reply); err != nil {
		return token{}, fmt.Errorf("mint installation token for %s: %w", repo, err)
	}
	if !validToken(reply.Token) {
		return token{}, fmt.Errorf("mint installation token for %s: the reply carries no valid token", repo)
	}
	tok := token{value: reply.Token, repo: repo, expires: reply.ExpiresAt}
	if err := checkGrant(reply, repo, want, c.now()); err != nil {
		c.revoke(ctx, tok)
		return token{}, fmt.Errorf("mint installation token for %s: %w", repo, err)
	}
	return tok, nil
}

// checkGrant refuses a token that is not exactly what was asked: the one
// repository, read on the requested permissions (GitHub adds metadata:read
// to every token), and a known, short lifetime.
func checkGrant(r tokenReply, repo string, want map[string]string, now time.Time) error {
	switch {
	case r.ExpiresAt.IsZero():
		return errors.New("no expires_at: refusing a credential of unknown lifetime")
	case !r.ExpiresAt.After(now):
		return fmt.Errorf("expired at %s", r.ExpiresAt.UTC().Format(time.RFC3339))
	case r.ExpiresAt.Sub(now) > maxTokenLifetime:
		return errors.New("lifetime exceeds two hours: refusing a long-lived credential")
	case len(r.Repositories) != 1 || !strings.EqualFold(r.Repositories[0].FullName, repo):
		return fmt.Errorf("granted %d repositories, want exactly %s", len(r.Repositories), repo)
	case len(r.Permissions) == 0:
		return errors.New("the reply names no permission")
	}
	for p, level := range r.Permissions {
		asked, ok := want[p]
		if p == "metadata" && !ok {
			asked, ok = "read", true // GitHub adds it to every installation token
		}
		if !ok || level != asked {
			return fmt.Errorf("granted %s:%s, beyond the %s access requested", textutil.Truncate(p, 32), textutil.Truncate(level, 16), asked)
		}
	}
	for p, asked := range want {
		if r.Permissions[p] != asked {
			return fmt.Errorf("granted %s:%s, not the %s access requested", textutil.Truncate(p, 32), textutil.Truncate(r.Permissions[p], 16), asked)
		}
	}
	return nil
}

// revoke revokes tok (DELETE /installation/token, authenticated by the
// token itself), detached from ctx's cancellation and bounded. A failure is
// logged, by repository and expiry, never the token: the token expires
// within the hour regardless.
func (c *Client) revoke(ctx context.Context, tok token) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	if err := c.call(rctx, http.MethodDelete, tok.value, "/installation/token", nil, http.StatusNoContent, maxReplyBytes, nil); err != nil {
		c.logger.Error("Could not revoke a GitHub App installation token: it expires on its own",
			"repository", tok.repo, "expires_at", tok.expires, "error", err)
	}
}

// withToken runs fn with a token for repo and perms, then revokes it. The
// whole read, mint included, is bounded by readTimeout.
func (c *Client) withToken(ctx context.Context, repo string, fn func(ctx context.Context, bearer string) error, perms ...string) error {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	tok, err := c.mint(ctx, repo, perms...)
	if err != nil {
		return err
	}
	defer c.revoke(ctx, tok)
	return fn(ctx, tok.value)
}

type accountReply struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

func (a accountReply) account(role string) (Account, error) {
	if err := validate.Login(a.Login); err != nil || a.ID < 1 {
		return Account{}, fmt.Errorf("%s: invalid account %q (id %d)", role, textutil.Truncate(a.Login, 64), a.ID)
	}
	return Account(a), nil
}

// pullRequestReply is the part of GET /repos/{o}/{r}/pulls/{n} used.
type pullRequestReply struct {
	Number int64  `json:"number"`
	State  string `json:"state"`
	Head   struct {
		SHA  string `json:"sha"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
	User   accountReply `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// permissionReply is the part of
// GET /repos/{o}/{r}/collaborators/{login}/permission used: the effective
// flags when present (custom roles), else the base role name.
type permissionReply struct {
	Permission string `json:"permission"`
	RoleName   string `json:"role_name"`
	User       *struct {
		accountReply
		Permissions *struct {
			Admin, Maintain, Push, Triage, Pull bool
		} `json:"permissions"`
	} `json:"user"`
}

func (r permissionReply) level() (string, error) {
	if r.User.Permissions != nil {
		f := r.User.Permissions
		switch {
		case f.Admin:
			return "admin", nil
		case f.Maintain:
			return "maintain", nil
		case f.Push:
			return "write", nil
		case f.Triage:
			return "triage", nil
		case f.Pull:
			return "read", nil
		}
		return "none", nil
	}
	for _, p := range []string{r.RoleName, r.Permission} {
		switch p {
		case "admin", "maintain", "write", "triage", "read", "none":
			return p, nil
		}
	}
	return "", fmt.Errorf("unknown permission %q", textutil.Truncate(r.Permission, 32))
}

// PullRequest reads PR number of repo, and its opener's permission on repo
// when the head lives there, with one token (pull_requests:read), revoked
// before it returns. The opener's permission is read for the account the
// PR names, by login, and must come back for the same account ID: a login
// renamed and taken by another account since is refused. Any reply that is
// not complete and consistent is an error.
func (c *Client) PullRequest(ctx context.Context, repo string, number uint32) (PRState, error) {
	path, err := repoPath(repo)
	if err != nil {
		return PRState{}, err
	}
	if number == 0 {
		return PRState{}, errors.New("pull request number must be positive")
	}
	var st PRState
	err = c.withToken(ctx, repo, func(ctx context.Context, bearer string) error {
		var pr pullRequestReply
		if err := c.get(ctx, bearer, path+"/pulls/"+strconv.FormatUint(uint64(number), 10), maxPRReplyBytes, &pr); err != nil {
			return err
		}
		if err := st.fill(pr, repo, number); err != nil {
			return err
		}
		if st.HeadRepo != repo {
			return nil // a fork, or a deleted head: never trusted, no permission read
		}
		st.OpenerPermission, err = c.permission(ctx, bearer, path, st.Opener)
		return err
	}, "pull_requests")
	if err != nil {
		return PRState{}, fmt.Errorf("read %s#%d: %w", repo, number, err)
	}
	return st, nil
}

// Permission reads who's permission on repo (admin, maintain, write,
// triage, read or none) with one token (metadata:read), revoked before it
// returns. It is read by who.Login, the login as GHES reported it, and must
// come back for who.ID: otherwise the error wraps ErrAccountMismatch.
func (c *Client) Permission(ctx context.Context, repo string, who Account) (string, error) {
	path, err := repoPath(repo)
	if err != nil {
		return "", err
	}
	if err := validate.Login(who.Login); err != nil || who.ID < 1 {
		return "", fmt.Errorf("permission of %q (id %d): invalid account", textutil.Truncate(who.Login, 64), who.ID)
	}
	var level string
	err = c.withToken(ctx, repo, func(ctx context.Context, bearer string) error {
		level, err = c.permission(ctx, bearer, path, who)
		return err
	}, "metadata")
	if err != nil {
		return "", fmt.Errorf("read the permission of %s#%d on %s: %w", who.Login, who.ID, repo, err)
	}
	return level, nil
}

// permission reads who's permission on the repository at path, by login,
// and requires the reply to be about who.ID.
func (c *Client) permission(ctx context.Context, bearer, path string, who Account) (string, error) {
	var perm permissionReply
	if err := c.get(ctx, bearer, path+"/collaborators/"+url.PathEscape(who.Login)+"/permission", maxReplyBytes, &perm); err != nil {
		return "", err
	}
	if perm.User == nil || perm.User.ID != who.ID {
		return "", fmt.Errorf("permission reply is not about account %d (%s): %w", who.ID, who.Login, ErrAccountMismatch)
	}
	return perm.level()
}

func (st *PRState) fill(pr pullRequestReply, repo string, number uint32) error {
	if pr.Number != int64(number) || !strings.EqualFold(pr.Base.Repo.FullName, repo) {
		return fmt.Errorf("the reply is for %q#%d", textutil.Truncate(pr.Base.Repo.FullName, 140), pr.Number)
	}
	switch pr.State {
	case "open":
		st.Open = true
	case "closed":
	default:
		return fmt.Errorf("unknown pull request state %q", textutil.Truncate(pr.State, 32))
	}
	if err := validate.CommitSHA(pr.Head.SHA); err != nil {
		return fmt.Errorf("head: %w", err)
	}
	st.HeadSHA = pr.Head.SHA
	if pr.Head.Repo != nil {
		if err := validate.RepoFullName(pr.Head.Repo.FullName); err != nil {
			return fmt.Errorf("head repository: %w", err)
		}
		st.HeadRepo = pr.Head.Repo.FullName
	}
	opener, err := pr.User.account("opener")
	if err != nil {
		return err
	}
	st.Opener = opener
	for _, l := range pr.Labels {
		if err := validate.LabelName(l.Name); err != nil {
			return err
		}
		st.Labels = append(st.Labels, l.Name)
	}
	return nil
}

type reviewReply struct {
	ID          int64        `json:"id"`
	User        accountReply `json:"user"`
	State       string       `json:"state"`
	CommitID    string       `json:"commit_id"`
	SubmittedAt *string      `json:"submitted_at"`
}

// Reviews reads every review of PR number of repo, oldest first, with one
// token (pull_requests:read), revoked before it returns. At most 10 pages of
// 100: a PR with more reviews is an error, never a partial list.
func (c *Client) Reviews(ctx context.Context, repo string, number uint32) ([]ReviewState, error) {
	path, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	if number == 0 {
		return nil, errors.New("pull request number must be positive")
	}
	var out []ReviewState
	err = c.withToken(ctx, repo, func(ctx context.Context, bearer string) error {
		for page := 1; ; page++ {
			if page > maxReviewPages {
				return fmt.Errorf("more than %d reviews: refusing a partial list", maxReviewPages*reviewsPerPage)
			}
			var batch []reviewReply
			q := fmt.Sprintf("%s/pulls/%d/reviews?per_page=%d&page=%d", path, number, reviewsPerPage, page)
			if err := c.get(ctx, bearer, q, maxReviewBytes, &batch); err != nil {
				return err
			}
			for _, r := range batch {
				rs, err := r.state()
				if err != nil {
					return err
				}
				out = append(out, rs)
			}
			if len(batch) < reviewsPerPage {
				return nil
			}
		}
	}, "pull_requests")
	if err != nil {
		return nil, fmt.Errorf("read the reviews of %s#%d: %w", repo, number, err)
	}
	return out, nil
}

func (r reviewReply) state() (ReviewState, error) {
	user, err := r.User.account("reviewer")
	if err != nil {
		return ReviewState{}, err
	}
	rs := ReviewState{ID: r.ID, User: user, State: r.State, CommitID: r.CommitID}
	switch {
	case r.ID < 1:
		return ReviewState{}, fmt.Errorf("review id %d", r.ID)
	case validate.CommitSHA(r.CommitID) != nil:
		return ReviewState{}, fmt.Errorf("review %d: invalid commit", r.ID)
	}
	switch r.State {
	case "APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING":
	default:
		return ReviewState{}, fmt.Errorf("review %d: unknown state %q", r.ID, textutil.Truncate(r.State, 32))
	}
	if r.SubmittedAt != nil {
		if rs.SubmittedAt, err = validate.Timestamp(*r.SubmittedAt); err != nil {
			return ReviewState{}, fmt.Errorf("review %d: %w", r.ID, err)
		}
	}
	return rs, nil
}

// Provider (V1.1 spec 3.1): the GitHub App client is the GitHub driver. The
// webhook secret is a parameter, the App key stays in Client, and the
// pull_request_review and label deliveries keep their own path in
// internal/api until the handler is provider-neutral: ParseEvent decodes
// pull_request deliveries only.

// Name implements Provider.
func (c *Client) Name() string { return ProviderGitHub }

// VerifyWebhook implements Provider: the exact HMAC-SHA256 of the body in
// X-Hub-Signature-256.
func (c *Client) VerifyWebhook(req *http.Request, secret []byte) ([]byte, error) {
	body, err := readWebhookBody(req)
	if err != nil {
		return nil, err
	}
	if err := validate.VerifySignature(secret, body, req.Header.Get(validate.SignatureHeader)); err != nil {
		return nil, err
	}
	restoreBody(req, body)
	return body, nil
}

// ParseEvent implements Provider for a pull_request delivery.
func (c *Client) ParseEvent(payload []byte) (*Event, error) {
	pr, err := validate.ParsePullRequest(payload)
	if err != nil {
		return nil, err
	}
	return &Event{
		Action: pr.Action, ProjectID: pr.Repo, Project: pr.Repo, IID: pr.Number,
		HeadRef: pr.HeadRef, HeadSHA: pr.HeadSHA, HeadProject: pr.HeadRepo, CloneURL: pr.CloneURL,
		Author:    Account{Login: pr.OpenerLogin, ID: pr.OpenerID},
		Sender:    Account{Login: pr.SenderLogin, ID: pr.SenderID},
		UpdatedAt: pr.UpdatedAt, Label: pr.Label,
	}, nil
}

// GetMRState implements Provider: projectID is owner/repo, mrIID the pull
// request number.
func (c *Client) GetMRState(ctx context.Context, projectID, mrIID string) (*MRState, error) {
	number, err := validate.MergeRequestIID(mrIID)
	if err != nil {
		return nil, err
	}
	pr, err := c.PullRequest(ctx, projectID, number)
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
func (c *Client) GetApprovals(ctx context.Context, projectID, mrIID string) ([]Approval, error) {
	number, err := validate.MergeRequestIID(mrIID)
	if err != nil {
		return nil, err
	}
	reviews, err := c.Reviews(ctx, projectID, number)
	if err != nil {
		return nil, err
	}
	return standingApprovals(reviews), nil
}

// standingApprovals keeps the accounts whose latest review, oldest first as
// Reviews returns them, is an approval. A comment changes nothing; a change
// request or a dismissal withdraws, and a pending review was never
// submitted.
func standingApprovals(reviews []ReviewState) []Approval {
	latest := map[int64]ReviewState{}
	var order []int64
	for _, r := range reviews {
		switch r.State {
		case "APPROVED", "CHANGES_REQUESTED", "DISMISSED":
			if _, seen := latest[r.User.ID]; !seen {
				order = append(order, r.User.ID)
			}
			latest[r.User.ID] = r
		}
	}
	var out []Approval
	for _, id := range order {
		if r := latest[id]; r.State == "APPROVED" {
			out = append(out, Approval{User: r.User, CommitSHA: r.CommitID})
		}
	}
	return out
}
