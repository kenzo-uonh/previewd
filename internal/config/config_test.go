package config

import (
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
	t.Setenv("PREVIEWD_WEBHOOK_SECRET", "s3cret")
	t.Setenv("PREVIEWD_GHES_URL", "https://ghes.corp")
	t.Setenv("PREVIEWD_GITHUB_APP_ID", "31337")
	t.Setenv("PREVIEWD_TLS_CERT_FILE", "/etc/previewd/tls.pem")
	t.Setenv("PREVIEWD_TLS_KEY_CREDENTIAL", "tls-key")
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
