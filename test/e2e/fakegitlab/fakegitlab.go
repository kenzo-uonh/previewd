//go:build e2e

// Package fakegitlab is the GitLab the E2E suite runs previewd's GitLab
// driver against: the REST API v4 subset previewd reads, over HTTPS with the
// test certificate of net/http/httptest, authenticated by one access token in
// PRIVATE-TOKEN, with the archive endpoint served by git archive from real
// bare repositories. A test tool, behind the e2e build tag: never part of a
// previewd build.
//
// Every request that is not authenticated, or that carries the token
// anywhere but the PRIVATE-TOKEN header, is refused and recorded in the
// ledger: a suite asserts the ledger is empty.
package fakegitlab

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Account is a GitLab user.
type Account struct {
	ID       int64
	Username string
}

// Member is a project member: AccessLevel 30 is Developer.
type Member struct {
	Account
	State       string // "active" or "blocked"
	AccessLevel int
}

// MergeRequest is a merge request of a project.
type MergeRequest struct {
	State           string // opened, closed, merged, locked
	SHA             string
	SourceProjectID int64
	Author          Account
	Labels          []string
	Approvers       []Account
}

// Project is a project with its bare repository (RepoDir, "" for none).
type Project struct {
	ID       int64
	Path     string
	RepoDir  string
	Members  map[int64]Member
	Requests map[uint32]*MergeRequest
}

// Fake is a GitLab server.
type Fake struct {
	token string
	srv   *httptest.Server

	mu       sync.Mutex
	projects map[int64]*Project
	ledger   []string
}

// New starts a fake GitLab that accepts token. Close it when done.
func New(token string) *Fake {
	f := &Fake{token: token, projects: map[int64]*Project{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v4/projects/{path}", f.project)
	mux.HandleFunc("GET /api/v4/projects/{id}/merge_requests/{iid}", f.guard(f.mergeRequest))
	mux.HandleFunc("GET /api/v4/projects/{id}/merge_requests/{iid}/approvals", f.guard(f.approvals))
	mux.HandleFunc("GET /api/v4/projects/{id}/members/all/{uid}", f.guard(f.member))
	mux.HandleFunc("GET /api/v4/projects/{id}/repository/archive.tar.gz", f.guard(f.archive))
	f.srv = httptest.NewTLSServer(mux)
	return f
}

// Close stops the server.
func (f *Fake) Close() { f.srv.Close() }

// URL is the server's https base URL.
func (f *Fake) URL() string { return f.srv.URL }

// CAPEM is the certificate a client must trust (PREVIEWD_GITLAB_CA_FILE).
func (f *Fake) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

// Ledger is every refused request, "METHOD path: reason".
func (f *Fake) Ledger() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ledger...)
}

// Edit runs fn on the project id under the server's lock, creating it
// (with path) if it does not exist.
func (f *Fake) Edit(id int64, path string, fn func(p *Project)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.projects[id]
	if !ok {
		p = &Project{ID: id, Path: path, Members: map[int64]Member{}, Requests: map[uint32]*MergeRequest{}}
		f.projects[id] = p
	}
	fn(p)
}

func (f *Fake) refuse(w http.ResponseWriter, r *http.Request, code int, why string) {
	f.mu.Lock()
	f.ledger = append(f.ledger, r.Method+" "+r.URL.Path+": "+why)
	f.mu.Unlock()
	reply(w, code, map[string]string{"message": strconv.Itoa(code) + " " + why})
}

// authenticated refuses a request that does not carry the token in
// PRIVATE-TOKEN alone.
func (f *Fake) authenticated(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Header.Get("PRIVATE-TOKEN") != f.token:
		f.refuse(w, r, http.StatusUnauthorized, "token missing or wrong")
		return false
	case strings.Contains(r.URL.String(), f.token) || r.Header.Get("Authorization") != "":
		f.refuse(w, r, http.StatusBadRequest, "token outside PRIVATE-TOKEN")
		return false
	}
	return true
}

// project answers GET /projects/:path with the project at that path (one
// URL-encoded segment), as GitLab does for a namespaced path.
func (f *Fake) project(w http.ResponseWriter, r *http.Request) {
	if !f.authenticated(w, r) {
		return
	}
	path := r.PathValue("path")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.projects {
		if p.Path == path {
			reply(w, http.StatusOK, map[string]any{"id": p.ID, "path_with_namespace": p.Path})
			return
		}
	}
	f.ledger = append(f.ledger, r.Method+" "+r.URL.Path+": no such project")
	reply(w, http.StatusNotFound, map[string]string{"message": "404 Project Not Found"})
}

func (f *Fake) guard(h func(w http.ResponseWriter, r *http.Request, p *Project)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !f.authenticated(w, r) {
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		f.mu.Lock()
		p := f.projects[id]
		f.mu.Unlock()
		if err != nil || p == nil {
			f.refuse(w, r, http.StatusNotFound, "no such project (a path is not an id)")
			return
		}
		h(w, r, p)
	}
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func user(a Account) map[string]any { return map[string]any{"id": a.ID, "username": a.Username} }

func (f *Fake) request(w http.ResponseWriter, r *http.Request, p *Project) *MergeRequest {
	iid, err := strconv.ParseUint(r.PathValue("iid"), 10, 32)
	f.mu.Lock()
	mr := p.Requests[uint32(iid)]
	f.mu.Unlock()
	if err != nil || mr == nil {
		f.refuse(w, r, http.StatusNotFound, "no such merge request")
		return nil
	}
	return mr
}

func (f *Fake) mergeRequest(w http.ResponseWriter, r *http.Request, p *Project) {
	mr := f.request(w, r, p)
	if mr == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	iid, _ := strconv.ParseUint(r.PathValue("iid"), 10, 32)
	reply(w, http.StatusOK, map[string]any{
		"iid": iid, "project_id": p.ID, "state": mr.State, "sha": mr.SHA,
		"source_project_id": mr.SourceProjectID, "target_project_id": p.ID,
		"author": user(mr.Author), "labels": mr.Labels,
	})
}

func (f *Fake) approvals(w http.ResponseWriter, r *http.Request, p *Project) {
	mr := f.request(w, r, p)
	if mr == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	iid, _ := strconv.ParseUint(r.PathValue("iid"), 10, 32)
	approvedBy := []map[string]any{}
	for _, a := range mr.Approvers {
		approvedBy = append(approvedBy, map[string]any{"user": user(a)})
	}
	reply(w, http.StatusOK, map[string]any{"iid": iid, "project_id": p.ID, "approved_by": approvedBy})
}

func (f *Fake) member(w http.ResponseWriter, r *http.Request, p *Project) {
	uid, err := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	f.mu.Lock()
	m, ok := p.Members[uid]
	f.mu.Unlock()
	if err != nil || !ok {
		f.refuse(w, r, http.StatusNotFound, "not a member")
		return
	}
	reply(w, http.StatusOK, map[string]any{"id": m.ID, "username": m.Username, "state": m.State, "access_level": m.AccessLevel})
}

// archive serves git archive of ?sha= from the project's repository, as
// GitLab does: directly, with no redirect.
func (f *Fake) archive(w http.ResponseWriter, r *http.Request, p *Project) {
	sha := r.URL.Query().Get("sha")
	if p.RepoDir == "" || len(sha) != 40 || strings.Trim(sha, "0123456789abcdef") != "" {
		f.refuse(w, r, http.StatusNotFound, "no such commit")
		return
	}
	// #nosec G204 -- a test tool: RepoDir is the suite's own, sha is 40 lowercase hex digits.
	cmd := exec.CommandContext(r.Context(), "git", "-C", p.RepoDir, "archive", "--format=tar.gz",
		fmt.Sprintf("--prefix=%s-%s-%s/", p.Path[strings.LastIndex(p.Path, "/")+1:], sha, sha), sha)
	// No user or system configuration: core.autocrlf and attributes of the
	// host must not change the bytes of an archive.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
	out, err := cmd.Output()
	if err != nil {
		f.refuse(w, r, http.StatusNotFound, "git archive failed")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	_, _ = w.Write(out)
}
