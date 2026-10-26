package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// The forges previewd serves (PREVIEWD_VCS_PROVIDER). The values equal
// vcs.ProviderGitHub, vcs.ProviderGitLab and vcs.ProviderForgejo: config
// imports no internal package but the validate leaf. Gitea is served as
// forgejo: it speaks the same API.
const (
	providerGitHub  = "github"
	providerGitLab  = "gitlab"
	providerForgejo = "forgejo"
)

// githubKeys, gitlabKeys and forgejoKeys are the keys that only make sense
// for one forge. Setting another forge's key is a contradiction, refused at
// start: a stale GHES block left in a GitLab deployment (or any other pair)
// is a misconfiguration to surface, never a value to ignore.
func githubKeys() []string {
	return []string{"PREVIEWD_GHES_URL", "PREVIEWD_GHES_CA_FILE", "PREVIEWD_GITHUB_APP_ID", "PREVIEWD_GITHUB_APP_KEY_CREDENTIAL"}
}

func gitlabKeys() []string {
	return []string{"PREVIEWD_GITLAB_URL", "PREVIEWD_GITLAB_CA_FILE", "PREVIEWD_GITLAB_TOKEN_CREDENTIAL", "PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL"}
}

func forgejoKeys() []string {
	return []string{"PREVIEWD_FORGEJO_URL", "PREVIEWD_FORGEJO_CA_FILE", "PREVIEWD_FORGEJO_TOKEN_CREDENTIAL", "PREVIEWD_FORGEJO_WEBHOOK_SECRET_CREDENTIAL"}
}

// forge is the settings of the forge being served; the other's are zero.
type forge struct {
	ghesURL, ghesCAFile, appKey string
	appID                       int64

	gitlabURL, gitlabCAFile                     string
	gitlabTokenCredential, gitlabHookCredential string

	forgejoURL, forgejoCAFile                     string
	forgejoTokenCredential, forgejoHookCredential string
}

// vcsProvider reads PREVIEWD_VCS_PROVIDER: exactly "github", "gitlab" or
// "forgejo", "github" when unset. Anything else, case and padding included,
// is an error: a typo never selects a forge.
func vcsProvider() (string, error) {
	v, set := os.LookupEnv("PREVIEWD_VCS_PROVIDER")
	switch {
	case !set, v == providerGitHub:
		return providerGitHub, nil
	case v == providerGitLab, v == providerForgejo:
		return v, nil
	}
	return "", fmt.Errorf("invalid PREVIEWD_VCS_PROVIDER %s: want %s, %s or %s", validate.Quote(v), providerGitHub, providerGitLab, providerForgejo)
}

// loadForge reads the keys of provider and refuses those of the others.
func loadForge(provider string) (forge, error) {
	switch provider {
	case providerGitLab:
		return loadGitLab()
	case providerForgejo:
		return loadForgejo()
	}
	return loadGitHub()
}

// rejectKeys refuses every key of the forges other than provider's.
func rejectKeys(provider string, others ...[]string) error {
	for _, keys := range others {
		for _, k := range keys {
			if os.Getenv(k) != "" {
				return fmt.Errorf("%s is set but PREVIEWD_VCS_PROVIDER=%s: remove it, or select the forge it belongs to", k, provider)
			}
		}
	}
	return nil
}

// caFile reads an optional site CA bundle path: unset, or clean and
// absolute.
func caFile(name string) (string, error) {
	v := os.Getenv(name)
	if v != "" && (!filepath.IsAbs(v) || v != filepath.Clean(v)) {
		return "", fmt.Errorf("invalid %s %q: want a clean absolute path", name, v)
	}
	return v, nil
}

func loadGitHub() (forge, error) {
	if err := rejectKeys(providerGitHub, gitlabKeys(), forgejoKeys()); err != nil {
		return forge{}, err
	}
	var f forge
	var err error
	if f.ghesURL, err = validate.GHESURL(os.Getenv("PREVIEWD_GHES_URL")); err != nil {
		return forge{}, fmt.Errorf("PREVIEWD_GHES_URL is required: %w", err)
	}
	f.ghesCAFile = os.Getenv("PREVIEWD_GHES_CA_FILE")
	if f.appID, err = strconv.ParseInt(os.Getenv("PREVIEWD_GITHUB_APP_ID"), 10, 64); err != nil || f.appID < 1 {
		return forge{}, fmt.Errorf("PREVIEWD_GITHUB_APP_ID is required: a positive integer")
	}
	if f.appKey, err = credentialName("PREVIEWD_GITHUB_APP_KEY_CREDENTIAL", defaultAppKeyCredential); err != nil {
		return forge{}, err
	}
	return f, nil
}

func loadGitLab() (forge, error) {
	if err := rejectKeys(providerGitLab, githubKeys(), forgejoKeys()); err != nil {
		return forge{}, err
	}
	var f forge
	var err error
	if f.gitlabURL, err = validate.GitLabURL(os.Getenv("PREVIEWD_GITLAB_URL")); err != nil {
		return forge{}, fmt.Errorf("PREVIEWD_GITLAB_URL is required: %w", err)
	}
	if f.gitlabCAFile, err = caFile("PREVIEWD_GITLAB_CA_FILE"); err != nil {
		return forge{}, err
	}
	if f.gitlabTokenCredential, err = credentialName("PREVIEWD_GITLAB_TOKEN_CREDENTIAL", defaultGitLabTokenCredential); err != nil {
		return forge{}, err
	}
	if f.gitlabHookCredential, err = credentialName("PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL", defaultGitLabHookCredential); err != nil {
		return forge{}, err
	}
	return f, nil
}

func loadForgejo() (forge, error) {
	if err := rejectKeys(providerForgejo, githubKeys(), gitlabKeys()); err != nil {
		return forge{}, err
	}
	var f forge
	var err error
	if f.forgejoURL, err = validate.ForgejoURL(os.Getenv("PREVIEWD_FORGEJO_URL")); err != nil {
		return forge{}, fmt.Errorf("PREVIEWD_FORGEJO_URL is required: %w", err)
	}
	if f.forgejoCAFile, err = caFile("PREVIEWD_FORGEJO_CA_FILE"); err != nil {
		return forge{}, err
	}
	if f.forgejoTokenCredential, err = credentialName("PREVIEWD_FORGEJO_TOKEN_CREDENTIAL", defaultForgejoTokenCredential); err != nil {
		return forge{}, err
	}
	if f.forgejoHookCredential, err = credentialName("PREVIEWD_FORGEJO_WEBHOOK_SECRET_CREDENTIAL", defaultForgejoHookCredential); err != nil {
		return forge{}, err
	}
	return f, nil
}
