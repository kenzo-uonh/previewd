package config

import (
	"strings"
	"testing"
	"time"
)

// Limits fail closed: a malformed value is a configuration error, never a
// silent fallback to the default.
func TestPositiveInt(t *testing.T) {
	const name = "PREVIEWD_TEST_LIMIT"

	t.Setenv(name, "")
	if n, err := positiveInt(name, 512); err != nil || n != 512 {
		t.Fatalf("unset = %d, %v; want default 512", n, err)
	}
	t.Setenv(name, "1024")
	if n, err := positiveInt(name, 512); err != nil || n != 1024 {
		t.Fatalf("1024 = %d, %v", n, err)
	}
	for _, bad := range []string{"0", "-1", "abc", "1.5", " 64", "64MiB", "1099511627777", "9223372036854775808"} {
		t.Setenv(name, bad)
		if n, err := positiveInt(name, 512); err == nil {
			t.Errorf("%q accepted as %d", bad, n)
		}
	}
}

func TestBoundedDuration(t *testing.T) {
	const name = "PREVIEWD_TEST_DURATION"
	t.Setenv(name, "")
	if d, err := boundedDuration(name, 15*time.Minute, time.Minute, 2*time.Hour); err != nil || d != 15*time.Minute {
		t.Fatalf("unset = %s, %v; want the default", d, err)
	}
	for v, want := range map[string]time.Duration{"1m": time.Minute, "2h": 2 * time.Hour, "90m": 90 * time.Minute} {
		t.Setenv(name, v)
		if d, err := boundedDuration(name, 15*time.Minute, time.Minute, 2*time.Hour); err != nil || d != want {
			t.Errorf("%s = %s, %v", v, d, err)
		}
	}
	for _, bad := range []string{"59s", "2h1m", "0", "-15m", "15", "15 m", "forever"} {
		t.Setenv(name, bad)
		if d, err := boundedDuration(name, 15*time.Minute, time.Minute, 2*time.Hour); err == nil {
			t.Errorf("%q accepted as %s", bad, d)
		}
	}
}

// minimalEnv sets the keys Load requires.
func minimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PREVIEWD_GHES_URL", "https://ghes.corp")
	t.Setenv("PREVIEWD_GITHUB_APP_ID", "31337")
	t.Setenv("PREVIEWD_TLS_CERT_FILE", "/etc/previewd/tls.pem")
	t.Setenv("PREVIEWD_TLS_KEY_CREDENTIAL", "tls-key")
	t.Setenv("PREVIEWD_ALLOWED_BASE_IMAGES", testBase)
}

const testBase = "busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"

// The build keys (V1 F2) fail closed: no allowlist, an image without its
// tag or its digest, a context cap out of 1..16384 MiB refuse to start.
func TestLoadBuildKeys(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowedBaseImages["docker.io/library/"+testBase] || len(cfg.AllowedBaseImages) != 1 || cfg.MaxBuildContextBytes != 512<<20 {
		t.Fatalf("defaults = %v, %d", cfg.AllowedBaseImages, cfg.MaxBuildContextBytes)
	}
	t.Setenv("PREVIEWD_MAX_BUILD_CONTEXT_MIB", "16384")
	if cfg, err = Load(); err != nil || cfg.MaxBuildContextBytes != 16384<<20 {
		t.Fatalf("16384 MiB = %v, %v", cfg, err)
	}
	for key, bad := range map[string]string{
		"PREVIEWD_ALLOWED_BASE_IMAGES":   "",
		"PREVIEWD_MAX_BUILD_CONTEXT_MIB": "0",
	} {
		t.Run(key+"="+bad, func(t *testing.T) {
			t.Setenv(key, bad)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%q accepted", key, bad)
			}
		})
	}
	for _, bad := range []string{"busybox:latest", "busybox@" + strings.TrimPrefix(testBase, "busybox:latest@"), testBase + ",", testBase + "," + testBase} {
		t.Run("image "+bad, func(t *testing.T) {
			t.Setenv("PREVIEWD_ALLOWED_BASE_IMAGES", bad)
			if _, err := Load(); err == nil {
				t.Fatalf("PREVIEWD_ALLOWED_BASE_IMAGES=%q accepted", bad)
			}
		})
	}
	for _, bad := range []string{"16385", "-1", "512MiB", "1.5"} {
		t.Run("cap "+bad, func(t *testing.T) {
			t.Setenv("PREVIEWD_MAX_BUILD_CONTEXT_MIB", bad)
			if _, err := Load(); err == nil {
				t.Fatalf("PREVIEWD_MAX_BUILD_CONTEXT_MIB=%q accepted", bad)
			}
		})
	}
}

// The approval keys fail closed: a malformed value refuses to start.
func TestLoadApprovalKeys(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Approvers) != 0 || cfg.LabelApproval || cfg.ApprovalLabel != "previewd-approved" || cfg.DeliveryMaxAge != 15*time.Minute {
		t.Fatalf("defaults = %+v", cfg)
	}
	t.Setenv("PREVIEWD_APPROVERS", "acme/shop:lead-dev#7")
	t.Setenv("PREVIEWD_LABEL_APPROVAL", "1")
	t.Setenv("PREVIEWD_APPROVAL_LABEL", "ok-to-preview")
	t.Setenv("PREVIEWD_DELIVERY_MAX_AGE", "30m")
	if cfg, err = Load(); err != nil {
		t.Fatal(err)
	}
	if a := cfg.Approvers["acme/shop"]; len(a) != 1 || a[0].ID != 7 || !cfg.LabelApproval ||
		cfg.ApprovalLabel != "ok-to-preview" || cfg.DeliveryMaxAge != 30*time.Minute {
		t.Fatalf("set = %+v", cfg)
	}
	for key, bad := range map[string]string{
		"PREVIEWD_APPROVERS":        "acme/shop:lead-dev",
		"PREVIEWD_LABEL_APPROVAL":   "true",
		"PREVIEWD_APPROVAL_LABEL":   "",
		"PREVIEWD_DELIVERY_MAX_AGE": "3h",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, bad)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%q accepted", key, bad)
			}
		})
	}
}

// The GHES and listener keys fail closed: missing, malformed or
// contradictory values refuse to start.
func TestLoadGHESAndListenerKeys(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GHESURL != "https://ghes.corp" || cfg.GitHubAppID != 31337 || cfg.GitHubAppKeyCredential != "github-app-key" ||
		cfg.TLSCertFile != "/etc/previewd/tls.pem" || cfg.TLSKeyCredential != "tls-key" || cfg.AllowPlaintextWebhooks ||
		cfg.WebhookAllowedCIDRs != nil {
		t.Fatalf("cfg = %+v", cfg)
	}
	t.Setenv("PREVIEWD_WEBHOOK_ALLOWED_CIDRS", "10.0.0.0/8")
	if cfg, err = Load(); err != nil || len(cfg.WebhookAllowedCIDRs) != 1 {
		t.Fatalf("CIDRs = %v, %v", cfg, err)
	}

	for name, env := range map[string]map[string]string{
		"no GHES URL":            {"PREVIEWD_GHES_URL": ""},
		"plaintext GHES URL":     {"PREVIEWD_GHES_URL": "http://ghes.corp"},
		"GHES URL with path":     {"PREVIEWD_GHES_URL": "https://ghes.corp/api/v3"},
		"no App ID":              {"PREVIEWD_GITHUB_APP_ID": ""},
		"zero App ID":            {"PREVIEWD_GITHUB_APP_ID": "0"},
		"App key as a path":      {"PREVIEWD_GITHUB_APP_KEY_CREDENTIAL": "/etc/previewd/app.pem"},
		"empty App key name":     {"PREVIEWD_GITHUB_APP_KEY_CREDENTIAL": ""},
		"no TLS certificate":     {"PREVIEWD_TLS_CERT_FILE": ""},
		"no TLS key":             {"PREVIEWD_TLS_KEY_CREDENTIAL": ""},
		"TLS key as a path":      {"PREVIEWD_TLS_KEY_CREDENTIAL": "../tls.key"},
		"plaintext and TLS":      {"PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS": "1"},
		"plaintext opt-in typo":  {"PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS": "yes", "PREVIEWD_TLS_CERT_FILE": "", "PREVIEWD_TLS_KEY_CREDENTIAL": ""},
		"CIDR with an empty one": {"PREVIEWD_WEBHOOK_ALLOWED_CIDRS": "10.0.0.0/8,"},
		"CIDR host bits":         {"PREVIEWD_WEBHOOK_ALLOWED_CIDRS": "10.1.2.3/8"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("%v accepted", env)
			}
		})
	}

	t.Setenv("PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS", "1")
	t.Setenv("PREVIEWD_TLS_CERT_FILE", "")
	t.Setenv("PREVIEWD_TLS_KEY_CREDENTIAL", "")
	if cfg, err = Load(); err != nil || !cfg.AllowPlaintextWebhooks {
		t.Fatalf("plaintext opt-in = %+v, %v", cfg, err)
	}
}

// Zero secrets in the environment: the webhook secret is a systemd
// credential name, and PREVIEWD_WEBHOOK_SECRET refuses to start whatever its
// value (even empty), without its value in the error.
func TestLoadWebhookSecretIsACredential(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebhookSecretCredential != "webhook_secret" {
		t.Fatalf("default credential = %q", cfg.WebhookSecretCredential)
	}
	t.Setenv("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL", "hook-hmac")
	if cfg, err = Load(); err != nil || cfg.WebhookSecretCredential != "hook-hmac" {
		t.Fatalf("named credential = %+v, %v", cfg, err)
	}
	for _, bad := range []string{"", "/etc/previewd/webhook_secret", "../webhook_secret", "a/b", ".."} {
		t.Setenv("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL", bad)
		if _, err := Load(); err == nil {
			t.Errorf("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL=%q accepted", bad)
		}
	}
	t.Setenv("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL", "hook-hmac")
	for _, legacy := range []string{"hook-s3cret-value", ""} {
		t.Setenv("PREVIEWD_WEBHOOK_SECRET", legacy)
		cfg, err := Load()
		if err == nil || cfg != nil {
			t.Fatalf("PREVIEWD_WEBHOOK_SECRET=%q accepted", legacy)
		}
		if legacy != "" && strings.Contains(err.Error(), legacy) {
			t.Fatalf("the refusal quotes the secret: %v", err)
		}
	}
}

// The D-V1-1 opt-in list and the re-validation bounds fail closed.
func TestLoadRevalidationAndFullSecrets(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FullSecretsRepos) != 0 || cfg.RevalidateInterval != 10*time.Minute || cfg.RevalidateGrace != time.Hour {
		t.Fatalf("defaults = %+v", cfg)
	}
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "acme/app,acme/web")
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_INTERVAL", "5m")
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_GRACE", "5m")
	if cfg, err = Load(); err != nil {
		t.Fatal(err)
	}
	if !cfg.FullSecretsRepos["acme/app"] || !cfg.FullSecretsRepos["acme/web"] || len(cfg.FullSecretsRepos) != 2 ||
		cfg.RevalidateInterval != 5*time.Minute || cfg.RevalidateGrace != 5*time.Minute {
		t.Fatalf("set = %+v", cfg)
	}
	// An interval above the default grace raises the default grace to it.
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_GRACE", "")
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_INTERVAL", "1h")
	if cfg, err = Load(); err != nil || cfg.RevalidateGrace != time.Hour {
		t.Fatalf("grace with a 1h interval = %+v, %v", cfg, err)
	}
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_INTERVAL", "")
	for key, bad := range map[string]string{
		"PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS": "acme/app,,acme/web",
		"PREVIEWD_APPROVAL_REVALIDATE_INTERVAL":    "30s",
		"PREVIEWD_APPROVAL_REVALIDATE_GRACE":       "25h",
	} {
		t.Setenv(key, bad)
		if _, err := Load(); err == nil {
			t.Errorf("%s=%q accepted", key, bad)
		}
		t.Setenv(key, "")
	}
	for _, bad := range []string{"acme/app,acme/app", "acme", "acme/app ", "../x/y"} {
		t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS=%q accepted", bad)
		}
	}
	t.Setenv("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", "")
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_INTERVAL", "20m")
	t.Setenv("PREVIEWD_APPROVAL_REVALIDATE_GRACE", "10m")
	if _, err := Load(); err == nil {
		t.Error("a grace shorter than the interval accepted")
	}
}
