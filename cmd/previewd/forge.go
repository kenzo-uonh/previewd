package main

// The forge the daemon serves (PREVIEWD_VCS_PROVIDER, V1.1 spec 3.1): what
// authorizes a deploy, how its source is fetched and which webhook route is
// mounted all follow from it. Exactly one forge is wired; a daemon never
// falls back to the other.

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/kenzo-uonh/previewd/internal/api"
	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/secrets"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// forge is the wiring of one forge.
type forge struct {
	provider   string
	authorizer orchestrator.Authorizer
	fetch      orchestrator.FetchFunc
	// github is the GHES truth the approval handlers read; nil under GitLab,
	// whose driver the options carry.
	github  api.GitHub
	options []api.Option
}

// newForge wires the forge cfg selects. A credential that cannot be read, a
// client that is refused or an unknown provider is an error: the daemon does
// not start.
func newForge(cfg *config.Config, approvals orchestrator.Approvals, logger *slog.Logger) (forge, error) {
	switch cfg.VCSProvider {
	case vcs.ProviderGitLab:
		return newGitLabForge(cfg, logger)
	case vcs.ProviderGitHub:
		return newGitHubForge(cfg, approvals, logger)
	}
	return forge{}, fmt.Errorf("unknown forge %q", cfg.VCSProvider)
}

// newGitHubForge is the V1 wiring: approval gating through the GitHub App
// (C3) judged by the deploy gate (D4) before any build, and the commit
// tarball from GHES (H2, V1-I11) extracted under bounds.
func newGitHubForge(cfg *config.Config, approvals orchestrator.Approvals, logger *slog.Logger) (forge, error) {
	ghes, err := newGHESClient(cfg, logger)
	if err != nil {
		return forge{}, fmt.Errorf("GHES client (%s): %w", cfg.GHESURL, err)
	}
	if cfg.LabelApproval {
		logger.Error("Opt-in active: an approver's label approves untrusted code",
			"opt_in", "PREVIEWD_LABEL_APPROVAL", "label", cfg.ApprovalLabel)
	}
	if len(cfg.FullSecretsRepos) > 0 {
		logger.Error("Opt-in active: approved untrusted deploys of these repositories receive the trusted secret section",
			"opt_in", "PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "repositories", slices.Sorted(maps.Keys(cfg.FullSecretsRepos)))
	}
	authorizer, err := orchestrator.NewAuthorizer(orchestrator.AuthorizerConfig{
		GitHub:           ghes,
		Approvals:        approvals,
		Approvers:        cfg.Approvers,
		LabelApproval:    cfg.LabelApproval,
		ApprovalLabel:    cfg.ApprovalLabel,
		FullSecretsRepos: cfg.FullSecretsRepos,
		Logger:           logger,
	})
	if err != nil {
		return forge{}, fmt.Errorf("authorizer: %w", err)
	}
	fetcher, err := vcs.NewFetcher(ghes, cfg.MaxBuildContextBytes)
	if err != nil {
		return forge{}, fmt.Errorf("source fetcher: %w", err)
	}
	logger.Info("Source fetch armed", "forge", vcs.ProviderGitHub, "ghes_tarball", fetcher.Tarball(), "max_bytes", cfg.MaxBuildContextBytes)
	return forge{provider: vcs.ProviderGitHub, authorizer: authorizer, fetch: fetcher.Fetch, github: ghes}, nil
}

// newGitLabForge wires GitLab Self-Managed: the access token from its systemd
// credential, held in memory only, the deploy gate reading merge requests
// from GitLab, and the project archive as the source. Only merge requests of
// the project whose author can push deploy; approvals are not recorded yet.
func newGitLabForge(cfg *config.Config, logger *slog.Logger) (forge, error) {
	token, err := secrets.Credential(cfg.GitLabTokenCredential)
	if err != nil {
		return forge{}, fmt.Errorf("GitLab token: %w", err)
	}
	defer clear(token)
	var ca []byte
	if cfg.GitLabCAFile != "" {
		if ca, err = readBounded(cfg.GitLabCAFile, maxCABundleBytes); err != nil {
			return forge{}, fmt.Errorf("PREVIEWD_GITLAB_CA_FILE: %w", err)
		}
	}
	gitlab, err := vcs.NewGitLab(vcs.GitLabConfig{BaseURL: cfg.GitLabURL, Token: token, CAPEM: ca, Logger: logger})
	if err != nil {
		return forge{}, fmt.Errorf("GitLab client (%s): %w", cfg.GitLabURL, err)
	}
	authorizer, err := orchestrator.NewGitLabAuthorizer(gitlab, logger)
	if err != nil {
		return forge{}, fmt.Errorf("authorizer: %w", err)
	}
	fetcher, err := vcs.NewGitLabFetcher(gitlab, cfg.MaxBuildContextBytes)
	if err != nil {
		return forge{}, fmt.Errorf("source fetcher: %w", err)
	}
	logger.Info("Source fetch armed", "forge", vcs.ProviderGitLab, "gitlab_url", cfg.GitLabURL, "max_bytes", cfg.MaxBuildContextBytes)
	logger.Warn("GitLab approvals are not recorded yet: only merge requests of the project, authored by a member with Developer access or more, deploy",
		"forge", vcs.ProviderGitLab)
	return forge{provider: vcs.ProviderGitLab, authorizer: authorizer, fetch: fetcher.Fetch, options: []api.Option{api.WithProvider(gitlab)}}, nil
}
