package config

import "testing"

// Compose sidecars are off by default and bounded to three services.
func TestLoadComposeDefaults(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ComposeEnabled || cfg.ComposeMaxServices != 3 {
		t.Errorf("ComposeEnabled = %v, ComposeMaxServices = %d; want off, 3", cfg.ComposeEnabled, cfg.ComposeMaxServices)
	}
}

func TestLoadComposeKeys(t *testing.T) {
	minimalEnv(t)
	t.Setenv("PREVIEWD_COMPOSE_ENABLED", "1")
	t.Setenv("PREVIEWD_COMPOSE_MAX_SERVICES", "5")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ComposeEnabled || cfg.ComposeMaxServices != 5 {
		t.Errorf("ComposeEnabled = %v, ComposeMaxServices = %d; want on, 5", cfg.ComposeEnabled, cfg.ComposeMaxServices)
	}
}

func TestLoadComposeKeysFailClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"enabled true":      {"PREVIEWD_COMPOSE_ENABLED": "true"},
		"enabled 0":         {"PREVIEWD_COMPOSE_ENABLED": "0"},
		"enabled yes":       {"PREVIEWD_COMPOSE_ENABLED": "yes"},
		"max zero":          {"PREVIEWD_COMPOSE_ENABLED": "1", "PREVIEWD_COMPOSE_MAX_SERVICES": "0"},
		"max negative":      {"PREVIEWD_COMPOSE_ENABLED": "1", "PREVIEWD_COMPOSE_MAX_SERVICES": "-1"},
		"max above ceiling": {"PREVIEWD_COMPOSE_ENABLED": "1", "PREVIEWD_COMPOSE_MAX_SERVICES": "9"},
		"max not a number":  {"PREVIEWD_COMPOSE_ENABLED": "1", "PREVIEWD_COMPOSE_MAX_SERVICES": "three"},
		"max while off":     {"PREVIEWD_COMPOSE_MAX_SERVICES": "99"},
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
