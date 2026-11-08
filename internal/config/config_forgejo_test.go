package config

import (
	"strings"
	"testing"
)

// forgejoEnv is minimalEnv for a Forgejo deployment: the GHES keys are gone.
func forgejoEnv(t *testing.T) {
	t.Helper()
	minimalEnv(t)
	t.Setenv("PREVIEWD_GHES_URL", "")
	t.Setenv("PREVIEWD_GITHUB_APP_ID", "")
	t.Setenv("PREVIEWD_VCS_PROVIDER", "forgejo")
	t.Setenv("PREVIEWD_FORGEJO_URL", "https://forge.internal.corp")
}

func TestLoadForgejoKeys(t *testing.T) {
	forgejoEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VCSProvider != "forgejo" || cfg.ForgejoURL != "https://forge.internal.corp" || cfg.ForgejoCAFile != "" ||
		cfg.ForgejoTokenCredential != "forgejo-api-token" || cfg.ForgejoWebhookSecretCredential != "forgejo-webhook-secret" {
		t.Fatalf("cfg = %+v", cfg)
	}
	// The daemon reads the webhook secret from one place: the credential of
	// the forge it serves.
	if cfg.WebhookSecretCredential != "forgejo-webhook-secret" {
		t.Errorf("WebhookSecretCredential = %q, want the Forgejo one", cfg.WebhookSecretCredential)
	}
	if cfg.GHESURL != "" || cfg.GitHubAppID != 0 || cfg.GitHubAppKeyCredential != "" || cfg.GitLabURL != "" || cfg.GitLabTokenCredential != "" {
		t.Errorf("another forge's keys set under forgejo: %+v", cfg)
	}

	t.Setenv("PREVIEWD_FORGEJO_URL", "https://forge.internal.corp:3000/")
	t.Setenv("PREVIEWD_FORGEJO_TOKEN_CREDENTIAL", "fj-token")
	t.Setenv("PREVIEWD_FORGEJO_WEBHOOK_SECRET_CREDENTIAL", "fj-hook")
	t.Setenv("PREVIEWD_FORGEJO_CA_FILE", "/etc/previewd/forgejo-ca.pem")
	if cfg, err = Load(); err != nil {
		t.Fatal(err)
	}
	if cfg.ForgejoURL != "https://forge.internal.corp:3000" || cfg.ForgejoTokenCredential != "fj-token" ||
		cfg.ForgejoWebhookSecretCredential != "fj-hook" || cfg.WebhookSecretCredential != "fj-hook" ||
		cfg.ForgejoCAFile != "/etc/previewd/forgejo-ca.pem" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadForgejoKeysFailClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"provider case":          {"PREVIEWD_VCS_PROVIDER": "Forgejo"},
		"no Forgejo URL":         {"PREVIEWD_FORGEJO_URL": ""},
		"plaintext Forgejo URL":  {"PREVIEWD_FORGEJO_URL": "http://forge.corp"},
		"Forgejo URL with path":  {"PREVIEWD_FORGEJO_URL": "https://forge.corp/git"},
		"Forgejo URL user info":  {"PREVIEWD_FORGEJO_URL": "https://root:pw@forge.corp"},
		"token as a path":        {"PREVIEWD_FORGEJO_TOKEN_CREDENTIAL": "/run/secrets/token"},
		"empty token name":       {"PREVIEWD_FORGEJO_TOKEN_CREDENTIAL": ""},
		"secret as a path":       {"PREVIEWD_FORGEJO_WEBHOOK_SECRET_CREDENTIAL": "../secret"},
		"relative CA file":       {"PREVIEWD_FORGEJO_CA_FILE": "ca.pem"},
		"unclean CA file":        {"PREVIEWD_FORGEJO_CA_FILE": "/etc/previewd/../ca.pem"},
		"generic secret name":    {"PREVIEWD_WEBHOOK_SECRET_CREDENTIAL": "webhook_secret"},
		"label approval":         {"PREVIEWD_LABEL_APPROVAL": "1"},
		"GitHub approver syntax": {"PREVIEWD_APPROVERS": "acme/app:lead.dev"},
		// Two forges configured is a mistake to surface, not to guess at.
		"GHES URL under forgejo":    {"PREVIEWD_GHES_URL": "https://ghes.corp"},
		"App ID under forgejo":      {"PREVIEWD_GITHUB_APP_ID": "31337"},
		"App key under forgejo":     {"PREVIEWD_GITHUB_APP_KEY_CREDENTIAL": "github-app-key"},
		"GitLab URL under forgejo":  {"PREVIEWD_GITLAB_URL": "https://gitlab.corp"},
		"GitLab token under fj":     {"PREVIEWD_GITLAB_TOKEN_CREDENTIAL": "gitlab-api-token"},
		"GitLab hook under fj":      {"PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL": "gitlab-webhook-secret"},
		"GitLab CA under forgejo":   {"PREVIEWD_GITLAB_CA_FILE": "/etc/previewd/ca.pem"},
		"token in the environment":  {"PREVIEWD_FORGEJO_TOKEN": "fj-do-not-print"},
		"secret in the environment": {"PREVIEWD_FORGEJO_WEBHOOK_SECRET": "do-not-print"},
		"empty token in the env":    {"PREVIEWD_FORGEJO_TOKEN": ""},
	} {
		t.Run(name, func(t *testing.T) {
			forgejoEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("%v accepted", env)
			}
			if strings.Contains(err.Error(), "do-not-print") {
				t.Errorf("error echoes a secret: %v", err)
			}
		})
	}

	// The Forgejo keys are refused under the other forges.
	for _, provider := range []string{"github", "gitlab"} {
		for _, key := range forgejoKeys() {
			t.Run(provider+" "+key, func(t *testing.T) {
				if provider == "gitlab" {
					gitlabEnv(t)
				} else {
					minimalEnv(t)
				}
				t.Setenv(key, "/etc/previewd/forgejo")
				if _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("%s accepted under %s: %v", key, provider, err)
				}
			})
		}
	}
}

// Forgejo names: dots and underscores in owners and logins, no nesting.
func TestLoadForgejoApproversAndFullSecrets(t *testing.T) {
	forgejoEnv(t)
	t.Setenv("PREVIEWD_APPROVERS", "acme.corp/app_v2:lead.dev#7")
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "acme.corp/app_v2")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Approvers["acme.corp/app_v2"]; len(got) != 1 || got[0].ID != 7 || got[0].Login != "lead.dev" || !cfg.FullSecretsRepos["acme.corp/app_v2"] {
		t.Errorf("approvers = %+v, full secrets = %v", cfg.Approvers, cfg.FullSecretsRepos)
	}
	for _, bad := range []string{"acme/sub/app:lead#7", "acme/app.git:lead#7"} {
		t.Setenv("PREVIEWD_APPROVERS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("%q accepted as a Forgejo approver", bad)
		}
	}
	t.Setenv("PREVIEWD_APPROVERS", "")
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "acme/sub/app")
	if _, err := Load(); err == nil {
		t.Error("a nested path was accepted as a Forgejo repository")
	}
}
