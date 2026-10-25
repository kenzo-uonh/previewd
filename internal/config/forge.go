package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// The forges previewd serves (PREVIEWD_VCS_PROVIDER). The values equal
// vcs.ProviderGitHub and vcs.ProviderGitLab: config imports no internal
// package but the validate leaf.
const (
	providerGitHub = "github"
	providerGitLab = "gitlab"
)

// githubKeys and gitlabKeys are the keys that only make sense for one
// forge. Setting the other forge's key is a contradiction, refused at start:
// a stale GHES block left in a GitLab deployment (or the reverse) is a
// misconfiguration to surface, never a value to ignore.
func githubKeys() []string {
	return []string{"PREVIEWD_GHES_URL", "PREVIEWD_GHES_CA_FILE", "PREVIEWD_GITHUB_APP_ID", "PREVIEWD_GITHUB_APP_KEY_CREDENTIAL"}
}

func gitlabKeys() []string {
	return []string{"PREVIEWD_GITLAB_URL", "PREVIEWD_GITLAB_CA_FILE", "PREVIEWD_GITLAB_TOKEN_CREDENTIAL", "PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL"}
}

// forge is the settings of the forge being served; the other's are zero.
type forge struct {
	ghesURL, ghesCAFile, appKey string
	appID                       int64

	gitlabURL, gitlabCAFile                     string
	gitlabTokenCredential, gitlabHookCredential string
}

// vcsProvider reads PREVIEWD_VCS_PROVIDER: exactly "github" or "gitlab",
// "github" when unset. Anything else, case and padding included, is an
// error: a typo never selects a forge.
func vcsProvider() (string, error) {
	v, set := os.LookupEnv("PREVIEWD_VCS_PROVIDER")
	switch {
	case !set, v == providerGitHub:
		return providerGitHub, nil
	case v == providerGitLab:
		return providerGitLab, nil
	}
	return "", fmt.Errorf("invalid PREVIEWD_VCS_PROVIDER %s: want %s or %s", validate.Quote(v), providerGitHub, providerGitLab)
}

// loadForge reads the keys of provider and refuses those of the other.
func loadForge(provider string) (forge, error) {
	if provider == providerGitLab {
		return loadGitLab()
	}
	return loadGitHub()
}

func rejectKeys(keys []string, provider string) error {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return fmt.Errorf("%s is set but PREVIEWD_VCS_PROVIDER=%s: remove it, or select the forge it belongs to", k, provider)
		}
	}
	return nil
}

func loadGitHub() (forge, error) {
	if err := rejectKeys(gitlabKeys(), providerGitHub); err != nil {
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
	if err := rejectKeys(githubKeys(), providerGitLab); err != nil {
		return forge{}, err
	}
	var f forge
	var err error
	if f.gitlabURL, err = validate.GitLabURL(os.Getenv("PREVIEWD_GITLAB_URL")); err != nil {
		return forge{}, fmt.Errorf("PREVIEWD_GITLAB_URL is required: %w", err)
	}
	if f.gitlabCAFile = os.Getenv("PREVIEWD_GITLAB_CA_FILE"); f.gitlabCAFile != "" &&
		(!filepath.IsAbs(f.gitlabCAFile) || f.gitlabCAFile != filepath.Clean(f.gitlabCAFile)) {
		return forge{}, fmt.Errorf("invalid PREVIEWD_GITLAB_CA_FILE %q: want a clean absolute path", f.gitlabCAFile)
	}
	if f.gitlabTokenCredential, err = credentialName("PREVIEWD_GITLAB_TOKEN_CREDENTIAL", defaultGitLabTokenCredential); err != nil {
		return forge{}, err
	}
	if f.gitlabHookCredential, err = credentialName("PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL", defaultGitLabHookCredential); err != nil {
		return forge{}, err
	}
	return f, nil
}
