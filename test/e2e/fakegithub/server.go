//go:build e2e

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pull is the fake's state of one pull request.
type pull struct {
	State    string   `json:"state"` // open or closed
	HeadSHA  string   `json:"head_sha"`
	HeadRepo string   `json:"head_repo"` // "" for a deleted fork
	Opener   account  `json:"opener"`
	Labels   []string `json:"labels"`
}

type account struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

type permission struct {
	ID         int64  `json:"id"`
	Permission string `json:"permission"` // admin, maintain, write, triage, read, none
}

type review struct {
	ID       int64   `json:"id"`
	User     account `json:"user"`
	State    string  `json:"state"`
	CommitID string  `json:"commit_id"`
}

// minted is one installation token and what it may do.
type minted struct {
	repo    string
	perms   map[string]string
	expires time.Time
	revoked bool
}

type ghes struct {
	appID        int64
	installation int64
	appKey       *rsa.PublicKey
	logger       *slog.Logger

	mu     sync.Mutex
	pulls  map[string]pull       // owner/repo#n
	perms  map[string]permission // owner/repo/login
	revs   map[string][]review   // owner/repo#n
	tokens map[string]*minted    // token value -> grant
	misuse []string              // refused token uses, for the ledger
	calls  map[string]int        // reads by kind
	// Tarball API (H2): the bare repository of each owner/repo, and the
	// one-time archive codes issued (code -> used).
	gitDirs map[string]string
	codes   map[string]bool
}

func newGHES(appID, installation int64, key *rsa.PublicKey, logger *slog.Logger) *ghes {
	return &ghes{appID: appID, installation: installation, appKey: key, logger: logger,
		pulls: map[string]pull{}, perms: map[string]permission{}, revs: map[string][]review{},
		tokens: map[string]*minted{}, calls: map[string]int{}, gitDirs: map[string]string{}, codes: map[string]bool{}}
}

func (g *ghes) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/installation", g.installationOf)
	mux.HandleFunc("POST /api/v3/app/installations/{id}/access_tokens", g.accessToken)
	mux.HandleFunc("DELETE /api/v3/installation/token", g.revoke)
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/pulls/{n}", g.pullRequest)
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/pulls/{n}/reviews", g.reviews)
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/collaborators/{login}/permission", g.permission)
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/tarball/{sha}", g.tarball)
	mux.HandleFunc("GET /_codeload/{owner}/{repo}/legacy.tar.gz/{sha}", g.codeload)
	// Control endpoints for the suite.
	mux.HandleFunc("PUT /_fake/pulls/{owner}/{repo}/{n}", g.setPull)
	mux.HandleFunc("PUT /_fake/permissions/{owner}/{repo}/{login}", g.setPermission)
	mux.HandleFunc("PUT /_fake/reviews/{owner}/{repo}/{n}", g.setReviews)
	mux.HandleFunc("GET /_fake/ledger", g.ledger)
	return mux
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"message": msg})
}

// appJWT verifies the App JWT as GHES does: RS256 with the App's public
// key, iss the App ID, iat not in the future, at most ten minutes of life.
func (g *ghes) appJWT(r *http.Request) error {
	jwt, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(jwt, ".")
	if !ok || len(parts) != 3 {
		return fmt.Errorf("no JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(g.appKey, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("JWT signature: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var c struct{ IAT, EXP, ISS int64 }
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	now := time.Now().Unix()
	if c.ISS != g.appID || c.IAT > now+60 || c.EXP <= now || c.EXP-c.IAT > 600 {
		return fmt.Errorf("JWT claims %+v", c)
	}
	return nil
}

func (g *ghes) installationOf(w http.ResponseWriter, r *http.Request) {
	if err := g.appJWT(r); err != nil {
		refuse(w, http.StatusUnauthorized, err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]int64{"id": g.installation})
}

func (g *ghes) accessToken(w http.ResponseWriter, r *http.Request) {
	if err := g.appJWT(r); err != nil {
		refuse(w, http.StatusUnauthorized, err.Error())
		return
	}
	if r.PathValue("id") != strconv.FormatInt(g.installation, 10) {
		refuse(w, http.StatusNotFound, "no such installation")
		return
	}
	var req struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || len(req.Repositories) != 1 {
		refuse(w, http.StatusUnprocessableEntity, "want exactly one repository")
		return
	}
	// The installation is on the e2e owner: the repository is e2e/<name>.
	repo := "e2e/" + req.Repositories[0]
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		refuse(w, http.StatusInternalServerError, err.Error())
		return
	}
	value := "ghs_" + hex.EncodeToString(buf)
	perms := map[string]string{"metadata": "read"}
	for p, level := range req.Permissions {
		perms[p] = level
	}
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	g.mu.Lock()
	g.tokens[value] = &minted{repo: repo, perms: perms, expires: expires}
	g.mu.Unlock()
	reply(w, http.StatusCreated, map[string]any{
		"token": value, "expires_at": expires.Format(time.RFC3339), "permissions": perms,
		"repository_selection": "selected", "repositories": []map[string]string{{"full_name": repo}},
	})
}

// authorize checks that the request's token is live, scoped to repo and
// grants perm; a refused use is recorded in the ledger.
func (g *ghes) authorize(w http.ResponseWriter, r *http.Request, repo, perm string) bool {
	value, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.tokens[value]
	switch {
	case !ok:
		g.misuse = append(g.misuse, "unknown token on "+r.URL.Path)
	case t.revoked:
		g.misuse = append(g.misuse, "revoked token on "+r.URL.Path)
	case time.Now().After(t.expires):
		g.misuse = append(g.misuse, "expired token on "+r.URL.Path)
	case !strings.EqualFold(t.repo, repo):
		g.misuse = append(g.misuse, "token for "+t.repo+" on "+repo)
	case t.perms[perm] == "":
		g.misuse = append(g.misuse, "token without "+perm+" on "+r.URL.Path)
	default:
		return true
	}
	refuse(w, http.StatusUnauthorized, "Bad credentials")
	return false
}

func (g *ghes) revoke(w http.ResponseWriter, r *http.Request) {
	value, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.tokens[value]
	if !ok || t.revoked {
		refuse(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	t.revoked = true
	w.WriteHeader(http.StatusNoContent)
}

func repoOf(r *http.Request) string { return r.PathValue("owner") + "/" + r.PathValue("repo") }

func (g *ghes) pullRequest(w http.ResponseWriter, r *http.Request) {
	repo := repoOf(r)
	if !g.authorize(w, r, repo, "pull_requests") {
		return
	}
	n, err := strconv.ParseInt(r.PathValue("n"), 10, 64)
	g.mu.Lock()
	p, ok := g.pulls[repo+"#"+r.PathValue("n")]
	g.calls["pull_request"]++
	g.mu.Unlock()
	if err != nil || !ok {
		refuse(w, http.StatusNotFound, "Not Found")
		return
	}
	var head any
	if p.HeadRepo != "" {
		head = map[string]string{"full_name": p.HeadRepo}
	}
	labels := make([]map[string]string, len(p.Labels))
	for i, l := range p.Labels {
		labels[i] = map[string]string{"name": l}
	}
	reply(w, http.StatusOK, map[string]any{
		"number": n, "state": p.State,
		"head": map[string]any{"sha": p.HeadSHA, "repo": head},
		"base": map[string]any{"repo": map[string]string{"full_name": repo}},
		"user": p.Opener, "labels": labels,
	})
}

func (g *ghes) permission(w http.ResponseWriter, r *http.Request) {
	repo := repoOf(r)
	if !g.authorize(w, r, repo, "metadata") {
		return
	}
	login := r.PathValue("login")
	g.mu.Lock()
	p, ok := g.perms[repo+"/"+login]
	g.calls["permission"]++
	g.mu.Unlock()
	if !ok {
		p = permission{Permission: "none"}
	}
	flags := map[string]bool{}
	switch p.Permission {
	case "admin":
		flags["admin"] = true
		fallthrough
	case "maintain":
		flags["maintain"] = true
		fallthrough
	case "write":
		flags["push"] = true
		fallthrough
	case "triage":
		flags["triage"] = true
		fallthrough
	case "read":
		flags["pull"] = true
	}
	reply(w, http.StatusOK, map[string]any{"permission": p.Permission, "role_name": p.Permission,
		"user": map[string]any{"login": login, "id": p.ID, "permissions": flags}})
}

func (g *ghes) reviews(w http.ResponseWriter, r *http.Request) {
	repo := repoOf(r)
	if !g.authorize(w, r, repo, "pull_requests") {
		return
	}
	g.mu.Lock()
	all := g.revs[repo+"#"+r.PathValue("n")]
	g.calls["reviews"]++
	g.mu.Unlock()
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	lo, hi := min((page-1)*100, len(all)), min(page*100, len(all))
	out := make([]map[string]any, 0, hi-lo)
	for _, rv := range all[lo:hi] {
		out = append(out, map[string]any{"id": rv.ID, "user": rv.User, "state": rv.State, "commit_id": rv.CommitID,
			"submitted_at": time.Now().UTC().Format(time.RFC3339)})
	}
	reply(w, http.StatusOK, out)
}

// tarball answers as GHES does: a redirect to the archive, on a one-time
// URL that carries its own credential.
func (g *ghes) tarball(w http.ResponseWriter, r *http.Request) {
	repo := repoOf(r)
	if !g.authorize(w, r, repo, "contents") {
		return
	}
	sha := r.PathValue("sha")
	g.mu.Lock()
	_, known := g.gitDirs[repo]
	g.calls["tarball"]++
	g.mu.Unlock()
	if !known || len(sha) != 40 || strings.Trim(sha, "0123456789abcdef") != "" {
		refuse(w, http.StatusNotFound, "Not Found")
		return
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		refuse(w, http.StatusInternalServerError, err.Error())
		return
	}
	code := hex.EncodeToString(buf)
	g.mu.Lock()
	g.codes[code] = false
	g.mu.Unlock()
	w.Header().Set("Location", "https://"+r.Host+"/_codeload/"+repo+"/legacy.tar.gz/"+sha+"?token="+code)
	w.WriteHeader(http.StatusFound)
}

// codeload streams git archive of the commit, once per code. An installation
// token sent here is misuse: the archive URL is its own credential.
func (g *ghes) codeload(w http.ResponseWriter, r *http.Request) {
	repo, sha, code := repoOf(r), r.PathValue("sha"), r.URL.Query().Get("token")
	g.mu.Lock()
	if r.Header.Get("Authorization") != "" {
		g.misuse = append(g.misuse, "credential sent to the archive host for "+repo)
	}
	used, issued := g.codes[code]
	dir := g.gitDirs[repo]
	if issued && !used {
		g.codes[code] = true
		g.calls["archive"]++
	}
	g.mu.Unlock()
	if !issued || used || dir == "" {
		refuse(w, http.StatusNotFound, "Not Found")
		return
	}
	owner, name, _ := strings.Cut(repo, "/")
	// #nosec G204 -- test tool: sha checked by the tarball API, dir from the command line.
	cmd := exec.CommandContext(r.Context(), "git", "--git-dir", dir, "archive", "--format=tar.gz",
		"--prefix="+owner+"-"+name+"-"+sha[:7]+"/", sha)
	cmd.Stdout = w
	w.Header().Set("Content-Type", "application/x-gzip")
	if err := cmd.Run(); err != nil {
		g.logger.Error("git archive failed", "repo", repo, "sha", sha, "error", err)
	}
}

func (g *ghes) setPull(w http.ResponseWriter, r *http.Request) {
	var p pull
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		refuse(w, http.StatusBadRequest, err.Error())
		return
	}
	g.mu.Lock()
	g.pulls[repoOf(r)+"#"+r.PathValue("n")] = p
	g.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (g *ghes) setPermission(w http.ResponseWriter, r *http.Request) {
	var p permission
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		refuse(w, http.StatusBadRequest, err.Error())
		return
	}
	g.mu.Lock()
	g.perms[repoOf(r)+"/"+r.PathValue("login")] = p
	g.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (g *ghes) setReviews(w http.ResponseWriter, r *http.Request) {
	var rs []review
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		refuse(w, http.StatusBadRequest, err.Error())
		return
	}
	g.mu.Lock()
	g.revs[repoOf(r)+"#"+r.PathValue("n")] = rs
	g.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// ledger reports the tokens minted, revoked and still live, every refused
// token use, and the reads served: the suite requires every token revoked
// and no misuse.
func (g *ghes) ledger(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	live, revoked, scopes := 0, 0, map[string]int{}
	for _, t := range g.tokens {
		if t.revoked {
			revoked++
		} else if time.Now().Before(t.expires) {
			live++
		}
		for p, level := range t.perms {
			scopes[p+":"+level]++
		}
	}
	reply(w, http.StatusOK, map[string]any{"minted": len(g.tokens), "revoked": revoked, "live": live,
		"scopes": scopes, "misuse": g.misuse, "reads": g.calls})
}
