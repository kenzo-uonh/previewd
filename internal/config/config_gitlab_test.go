package config

import (
	"strings"
	"testing"
)

// gitlabEnv is minimalEnv for a GitLab deployment: the GHES keys are gone.
func gitlabEnv(t *testing.T) {
	t.Helper()
	minimalEnv(t)
	t.Setenv("PREVIEWD_GHES_URL", "")
	t.Setenv("PREVIEWD_GITHUB_APP_ID", "")
	t.Setenv("PREVIEWD_VCS_PROVIDER", "gitlab")
	t.Setenv("PREVIEWD_GITLAB_URL", "https://gitlab.internal.corp")
}

// GitHub stays the default: a V1 environment loads unchanged.
func TestLoadVCSProviderDefaultsToGitHub(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VCSProvider != "github" || cfg.GitLabURL != "" || cfg.WebhookSecretCredential != "webhook_secret" {
		t.Errorf("cfg = %q, %q, %q", cfg.VCSProvider, cfg.GitLabURL, cfg.WebhookSecretCredential)
	}
	t.Setenv("PREVIEWD_VCS_PROVIDER", "github")
	if cfg, err = Load(); err != nil || cfg.VCSProvider != "github" {
		t.Errorf("explicit github = %v, %v", cfg, err)
	}
}

func TestLoadGitLabKeys(t *testing.T) {
	gitlabEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VCSProvider != "gitlab" || cfg.GitLabURL != "https://gitlab.internal.corp" || cfg.GitLabCAFile != "" ||
		cfg.GitLabTokenCredential != "gitlab-api-token" || cfg.GitLabWebhookSecretCredential != "gitlab-webhook-secret" {
		t.Fatalf("cfg = %+v", cfg)
	}
	// The daemon reads the webhook secret from one place: the credential of
	// the forge it serves.
	if cfg.WebhookSecretCredential != "gitlab-webhook-secret" {
		t.Errorf("WebhookSecretCredential = %q, want the GitLab one", cfg.WebhookSecretCredential)
	}
	// GHES keys are not required, and GitHub keys stay empty.
	if cfg.GHESURL != "" || cfg.GitHubAppID != 0 || cfg.GitHubAppKeyCredential != "" {
		t.Errorf("GitHub keys set under gitlab: %+v", cfg)
	}

	t.Setenv("PREVIEWD_GITLAB_URL", "https://gitlab.internal.corp:8443/")
	t.Setenv("PREVIEWD_GITLAB_TOKEN_CREDENTIAL", "gl-token")
	t.Setenv("PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL", "gl-hook")
	t.Setenv("PREVIEWD_GITLAB_CA_FILE", "/etc/previewd/gitlab-ca.pem")
	if cfg, err = Load(); err != nil {
		t.Fatal(err)
	}
	if cfg.GitLabURL != "https://gitlab.internal.corp:8443" || cfg.GitLabTokenCredential != "gl-token" ||
		cfg.GitLabWebhookSecretCredential != "gl-hook" || cfg.WebhookSecretCredential != "gl-hook" ||
		cfg.GitLabCAFile != "/etc/previewd/gitlab-ca.pem" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadGitLabKeysFailClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"unknown provider":          {"PREVIEWD_VCS_PROVIDER": "forgejo"},
		"provider case":             {"PREVIEWD_VCS_PROVIDER": "GitLab"},
		"provider with space":       {"PREVIEWD_VCS_PROVIDER": "gitlab "},
		"no GitLab URL":             {"PREVIEWD_GITLAB_URL": ""},
		"plaintext GitLab URL":      {"PREVIEWD_GITLAB_URL": "http://gitlab.corp"},
		"GitLab URL with path":      {"PREVIEWD_GITLAB_URL": "https://gitlab.corp/gitlab"},
		"GitLab URL with user info": {"PREVIEWD_GITLAB_URL": "https://root:pw@gitlab.corp"},
		"token as a path":           {"PREVIEWD_GITLAB_TOKEN_CREDENTIAL": "/run/secrets/token"},
		"empty token name":          {"PREVIEWD_GITLAB_TOKEN_CREDENTIAL": ""},
		"secret as a path":          {"PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL": "../secret"},
		"empty secret name":         {"PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL": ""},
		"relative CA file":          {"PREVIEWD_GITLAB_CA_FILE": "ca.pem"},
		// Two forges configured is a mistake to surface, not to guess at.
		"GHES URL under gitlab":     {"PREVIEWD_GHES_URL": "https://ghes.corp"},
		"App ID under gitlab":       {"PREVIEWD_GITHUB_APP_ID": "31337"},
		"GHES CA under gitlab":      {"PREVIEWD_GHES_CA_FILE": "/etc/previewd/ca.pem"},
		"generic secret name":       {"PREVIEWD_WEBHOOK_SECRET_CREDENTIAL": "webhook_secret"},
		"token in the environment":  {"PREVIEWD_GITLAB_TOKEN": "glpat-do-not-print"},
		"secret in the environment": {"PREVIEWD_GITLAB_WEBHOOK_SECRET": "do-not-print"},
		"empty token in the env":    {"PREVIEWD_GITLAB_TOKEN": ""},
	} {
		t.Run(name, func(t *testing.T) {
			gitlabEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("%v accepted", env)
			}
			for _, v := range env {
				if strings.Contains(v, "do-not-print") && strings.Contains(err.Error(), "do-not-print") {
					t.Errorf("error echoes a secret: %v", err)
				}
			}
		})
	}

	for name, env := range map[string]map[string]string{
		"GitLab URL under github":    {"PREVIEWD_GITLAB_URL": "https://gitlab.corp"},
		"GitLab token cred":          {"PREVIEWD_GITLAB_TOKEN_CREDENTIAL": "gl-token"},
		"GitLab webhook secret cred": {"PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL": "gl-hook"},
		"GitLab CA file":             {"PREVIEWD_GITLAB_CA_FILE": "/etc/previewd/ca.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			minimalEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("%v accepted under the github provider", env)
			}
		})
	}
}

// One grammar per forge: GitLab paths nest, GitHub's do not.
func TestLoadApproversFollowTheProvider(t *testing.T) {
	const nested = "acme/sub/app:lead.dev#7"
	gitlabEnv(t)
	t.Setenv("PREVIEWD_APPROVERS", nested)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Approvers["acme/sub/app"]; len(got) != 1 || got[0].ID != 7 || got[0].Login != "lead.dev" {
		t.Errorf("gitlab approvers = %+v", cfg.Approvers)
	}

	minimalEnv(t)
	t.Setenv("PREVIEWD_VCS_PROVIDER", "github")
	t.Setenv("PREVIEWD_APPROVERS", nested)
	if _, err := Load(); err == nil {
		t.Error("a nested path was accepted as a GitHub approver")
	}
	t.Setenv("PREVIEWD_APPROVERS", "")
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "acme/sub/app")
	if _, err := Load(); err == nil {
		t.Error("a nested path was accepted as a GitHub repository")
	}
}

// A label approves on GitHub only: GitLab has its own approval. An opt-in
// that cannot act is refused, never silently ignored.
func TestLoadGitLabRefusesTheLabelApproval(t *testing.T) {
	gitlabEnv(t)
	t.Setenv("PREVIEWD_LABEL_APPROVAL", "1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PREVIEWD_LABEL_APPROVAL") {
		t.Errorf("err = %v; want a refusal naming the key", err)
	}
}

// The full-secrets opt-in follows an approval, GitLab's included, and names
// projects as GitLab spells them.
func TestLoadGitLabFullSecretsOptIn(t *testing.T) {
	gitlabEnv(t)
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "acme/sub/app")
	cfg, err := Load()
	if err != nil || !cfg.FullSecretsRepos["acme/sub/app"] {
		t.Fatalf("Load = %v, %v", cfg, err)
	}
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "app")
	if _, err := Load(); err == nil {
		t.Error("a project without a namespace accepted")
	}
}
