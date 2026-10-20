//go:build e2e

package fakegitlab_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
	"github.com/kenzo-uonh/previewd/test/e2e/fakegitlab"
)

const (
	token     = "glpat-E2EONLYtoken0123456789"
	projectID = "15"
	path      = "acme/sub/app"
)

// git runs git in dir with a pinned identity and no user configuration, so
// the suite's repository and its commit IDs do not depend on the host.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.invalid", "GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.invalid",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo makes a repository with a safe commit and, after it, a commit that
// carries a symlink out of the tree.
func repo(t *testing.T) (dir, safe, hostile string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir = t.TempDir()
	git(t, dir, "init", "--quiet", "--initial-branch=main")
	must(t, os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644))
	must(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "bin", "run.sh"), []byte("#!/bin/sh\n"), 0o755))
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "--quiet", "-m", "safe")
	safe = git(t, dir, "rev-parse", "HEAD")
	must(t, os.Symlink("../../../etc/passwd", filepath.Join(dir, "escape")))
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "--quiet", "-m", "hostile")
	hostile = git(t, dir, "rev-parse", "HEAD")
	return dir, safe, hostile
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func client(t *testing.T, f *fakegitlab.Fake) *vcs.GitLab {
	t.Helper()
	g, err := vcs.NewGitLab(vcs.GitLabConfig{BaseURL: f.URL(), Token: []byte(token), CAPEM: f.CAPEM()})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The archive is streamed from git archive, extracted under the bounds, and
// a commit carrying a symlink out of the tree is refused whole.
func TestTarballStreamingFromGitArchive(t *testing.T) {
	dir, safe, hostile := repo(t)
	f := fakegitlab.New(token)
	defer f.Close()
	f.Edit(15, path, func(p *fakegitlab.Project) { p.RepoDir = dir })
	g := client(t, f)

	dest := filepath.Join(t.TempDir(), "src")
	must(t, g.FetchTarball(context.Background(), projectID, safe, dest, 1<<20))
	if got, err := os.ReadFile(filepath.Join(dest, "Dockerfile")); err != nil || string(got) != "FROM scratch\n" {
		t.Errorf("Dockerfile = %q, %v", got, err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "bin", "run.sh")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("run.sh = %v, %v", fi, err)
	}

	dest = filepath.Join(t.TempDir(), "src")
	err := g.FetchTarball(context.Background(), projectID, hostile, dest, 1<<20)
	if !errors.Is(err, vcs.ErrUnsafeArchive) {
		t.Errorf("hostile commit: err = %v, want ErrUnsafeArchive", err)
	}

	// The size cap holds on a real archive too.
	if err := g.FetchTarball(context.Background(), projectID, safe, filepath.Join(t.TempDir(), "src"), 8); err == nil {
		t.Error("an archive above the cap was accepted")
	}
	if l := f.Ledger(); len(l) != 0 {
		t.Errorf("refused requests: %v", l)
	}
}

// Approval verification: who approves now, matched to PREVIEWD_APPROVERS by
// account ID, follows the forge as approvals come and go, and a push moves
// the head the caller binds an approval to.
func TestApprovalVerification(t *testing.T) {
	f := fakegitlab.New(token)
	defer f.Close()
	const head = "0123456789abcdef0123456789abcdef01234567"
	lead := fakegitlab.Account{ID: 7, Username: "lead.dev"}
	other := fakegitlab.Account{ID: 8, Username: "second"}
	f.Edit(15, path, func(p *fakegitlab.Project) {
		p.Members[4242] = fakegitlab.Member{Account: fakegitlab.Account{ID: 4242, Username: "author"}, State: "active", AccessLevel: 30}
		p.Requests[7] = &fakegitlab.MergeRequest{State: "opened", SHA: head, SourceProjectID: 15,
			Author: fakegitlab.Account{ID: 4242, Username: "author"}, Approvers: []fakegitlab.Account{lead, other}}
	})
	g := client(t, f)
	approvers := []validate.Approver{{Login: "lead.dev", ID: 7}}

	got, err := g.GetApprovals(context.Background(), projectID, "7")
	must(t, err)
	if auth := vcs.Authorized(got, approvers); len(got) != 2 || len(auth) != 1 || auth[0].User.ID != 7 {
		t.Fatalf("approvals %+v, authorized %+v; want 2 and only #7", got, auth)
	}

	// The approver withdraws: nothing authorizes the merge request any more.
	f.Edit(15, path, func(p *fakegitlab.Project) { p.Requests[7].Approvers = []fakegitlab.Account{other} })
	got, err = g.GetApprovals(context.Background(), projectID, "7")
	must(t, err)
	if auth := vcs.Authorized(got, approvers); len(auth) != 0 {
		t.Errorf("a withdrawn approval still authorizes: %+v", auth)
	}

	// The same author on a fork is untrusted; in the project, a Developer is trusted.
	st, err := g.GetMRState(context.Background(), projectID, "7")
	must(t, err)
	if !st.Open || !st.Trusted || st.HeadSHA != head {
		t.Errorf("state = %+v", st)
	}
	f.Edit(15, path, func(p *fakegitlab.Project) { p.Requests[7].SourceProjectID = 88 })
	if st, err = g.GetMRState(context.Background(), projectID, "7"); err != nil || st.Trusted {
		t.Errorf("fork: %+v, %v; want untrusted", st, err)
	}
	f.Edit(15, path, func(p *fakegitlab.Project) { p.Requests[7].State = "merged" })
	if st, err = g.GetMRState(context.Background(), projectID, "7"); err != nil || st.Open {
		t.Errorf("merged: %+v, %v; want not open", st, err)
	}

	// A path is not an ID: the driver never sends one, and the fake would refuse it.
	if _, err := g.GetApprovals(context.Background(), path, "7"); err == nil {
		t.Error("a project path was accepted")
	}
	if l := f.Ledger(); len(l) != 0 {
		t.Errorf("refused requests: %v", l)
	}
}

// The token is the only way in: the fake refuses, and records, any other.
func TestTheFakeRefusesAWrongToken(t *testing.T) {
	f := fakegitlab.New(token)
	defer f.Close()
	f.Edit(15, path, func(p *fakegitlab.Project) {
		p.Requests[7] = &fakegitlab.MergeRequest{State: "opened", SHA: strings.Repeat("a", 40), SourceProjectID: 15,
			Author: fakegitlab.Account{ID: 1, Username: "x"}}
	})
	g, err := vcs.NewGitLab(vcs.GitLabConfig{BaseURL: f.URL(), Token: []byte("glpat-wrong"), CAPEM: f.CAPEM()})
	must(t, err)
	if _, err := g.GetMRState(context.Background(), projectID, "7"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want HTTP 401", err)
	}
	if len(f.Ledger()) != 1 {
		t.Errorf("ledger = %v, want the one refusal", f.Ledger())
	}
}

// The reconciler's fetch: the store keeps the project's path, the fetcher
// resolves it and streams the archive of the exact commit.
func TestFetcherResolvesThePathAndFetchesTheCommit(t *testing.T) {
	dir, safe, hostile := repo(t)
	f := fakegitlab.New(token)
	defer f.Close()
	f.Edit(15, path, func(p *fakegitlab.Project) { p.RepoDir = dir })
	fetcher, err := vcs.NewGitLabFetcher(client(t, f), 1<<20)
	must(t, err)

	dest := filepath.Join(t.TempDir(), "src")
	must(t, fetcher.Fetch(context.Background(), path, "https://gitlab.example/acme/sub/app.git", safe, dest))
	if got, err := os.ReadFile(filepath.Join(dest, "Dockerfile")); err != nil || string(got) != "FROM scratch\n" {
		t.Errorf("Dockerfile = %q, %v", got, err)
	}
	if err := fetcher.Fetch(context.Background(), path, "", hostile, filepath.Join(t.TempDir(), "src")); !errors.Is(err, vcs.ErrUnsafeArchive) {
		t.Errorf("hostile commit: err = %v, want ErrUnsafeArchive", err)
	}
	if err := fetcher.Fetch(context.Background(), "acme/renamed", "", safe, filepath.Join(t.TempDir(), "src")); err == nil {
		t.Error("a project that no longer has this path was fetched")
	}
	if l := f.Ledger(); len(l) != 1 || !strings.Contains(l[0], "no such project") {
		t.Errorf("ledger = %v; want the one refused lookup", l)
	}
}
