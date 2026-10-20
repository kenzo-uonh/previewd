package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/store"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// noApprovals is a store with no approval.
type noApprovals struct{}

func (noApprovals) LiveApproval(context.Context, string, string) (store.Approval, bool, error) {
	return store.Approval{}, false, nil
}

func gitlabConfig() *config.Config {
	return &config.Config{
		VCSProvider: "gitlab", GitLabURL: "https://gitlab.internal.corp", GitLabTokenCredential: "gitlab-api-token",
		MaxBuildContextBytes: 1 << 20,
	}
}

// credentials makes a credentials directory holding name = value.
func credentials(t *testing.T, name, value string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
}

func TestNewForgeWiresGitLab(t *testing.T) {
	credentials(t, "gitlab-api-token", "glpat-TESTONLYtokenvalue0123")
	f, err := newForge(gitlabConfig(), noApprovals{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.authorizer.(*orchestrator.GitLabAuthorizer); !ok {
		t.Errorf("authorizer is %T, want the GitLab gate", f.authorizer)
	}
	if f.fetch == nil || f.github != nil || len(f.options) != 1 {
		t.Errorf("fetch %v, github %v, options %d; want a fetcher, no GitHub client and the provider option", f.fetch != nil, f.github, len(f.options))
	}
	if f.provider != vcs.ProviderGitLab {
		t.Errorf("provider %q", f.provider)
	}
}

// Fails closed: a GitLab daemon without its token does not start, and does
// not fall back to a GitHub App it was not given.
func TestNewForgeRefusesGitLabWithoutItsToken(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	if _, err := newForge(gitlabConfig(), noApprovals{}, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "GitLab token") {
		t.Errorf("err = %v; want a refusal naming the GitLab token", err)
	}

	credentials(t, "gitlab-api-token", "token with spaces")
	if _, err := newForge(gitlabConfig(), noApprovals{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a malformed token was accepted")
	}

	credentials(t, "gitlab-api-token", "glpat-TESTONLYtokenvalue0123")
	cfg := gitlabConfig()
	cfg.GitLabCAFile = filepath.Join(t.TempDir(), "absent.pem")
	if _, err := newForge(cfg, noApprovals{}, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "PREVIEWD_GITLAB_CA_FILE") {
		t.Errorf("an unreadable CA bundle: err = %v", err)
	}
}

// A GitLab daemon without an approval store has no gate: it does not start.
func TestNewForgeRefusesGitLabWithoutAnApprovalStore(t *testing.T) {
	credentials(t, "gitlab-api-token", "glpat-TESTONLYtokenvalue0123")
	if _, err := newForge(gitlabConfig(), nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a GitLab gate without an approval store was wired")
	}
}

func TestNewForgeKeepsTheGitHubPathForGitHub(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	cfg := &config.Config{VCSProvider: "github", GHESURL: "https://ghes.corp", GitHubAppID: 1, GitHubAppKeyCredential: "github-app-key", MaxBuildContextBytes: 1 << 20}
	if _, err := newForge(cfg, noApprovals{}, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "GitHub App key") {
		t.Errorf("err = %v; want the GitHub App path", err)
	}
	cfg.VCSProvider = "bitbucket"
	if _, err := newForge(cfg, noApprovals{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("an unknown provider was wired")
	}
}

// Feedback follows PREVIEWD_FEEDBACK. Off is a nil interface, not a typed nil
// the reconciler would call.
func TestNewForgeWiresFeedbackOnlyWhenEnabled(t *testing.T) {
	credentials(t, "gitlab-api-token", "glpat-TESTONLYtokenvalue0123")
	cfg := gitlabConfig()
	cfg.Feedback = true
	f, err := newForge(cfg, noApprovals{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.feedback.(*vcs.Notifier); !ok {
		t.Errorf("feedback is %T, want the notifier", f.feedback)
	}
	cfg.Feedback = false
	if f, err = newForge(cfg, noApprovals{}, slog.New(slog.DiscardHandler)); err != nil || f.feedback != nil {
		t.Errorf("feedback = %v, %v; want none when disabled", f.feedback, err)
	}
}
