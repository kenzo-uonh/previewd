package config

import "testing"

// Developer feedback is on by default; the URL scheme follows the shipped
// Traefik entrypoint (plain HTTP).
func TestLoadFeedbackDefaults(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Feedback || cfg.PreviewScheme != "http" {
		t.Errorf("Feedback = %v, PreviewScheme = %q; want on, http", cfg.Feedback, cfg.PreviewScheme)
	}
}

func TestLoadFeedbackKeys(t *testing.T) {
	minimalEnv(t)
	t.Setenv("PREVIEWD_FEEDBACK", "0")
	t.Setenv("PREVIEWD_PREVIEW_URL_SCHEME", "https")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Feedback || cfg.PreviewScheme != "https" {
		t.Errorf("Feedback = %v, PreviewScheme = %q; want off, https", cfg.Feedback, cfg.PreviewScheme)
	}
	t.Setenv("PREVIEWD_FEEDBACK", "1")
	if cfg, err = Load(); err != nil || !cfg.Feedback {
		t.Errorf("explicit 1: %v, %v", cfg, err)
	}
}

func TestLoadFeedbackKeysFailClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"feedback true":    {"PREVIEWD_FEEDBACK": "true"},
		"feedback off":     {"PREVIEWD_FEEDBACK": "off"},
		"feedback 2":       {"PREVIEWD_FEEDBACK": "2"},
		"scheme ftp":       {"PREVIEWD_PREVIEW_URL_SCHEME": "ftp"},
		"scheme uppercase": {"PREVIEWD_PREVIEW_URL_SCHEME": "HTTPS"},
		"scheme with ://":  {"PREVIEWD_PREVIEW_URL_SCHEME": "https://"},
		"scheme padded":    {"PREVIEWD_PREVIEW_URL_SCHEME": "https "},
	} {
		t.Run(name, func(t *testing.T) {
			minimalEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("%v accepted", env)
			}
		})
	}
}
