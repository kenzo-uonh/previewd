package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestLoadTriggerAPI(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TriggerAPI || cfg.TriggerTokenCredential != "" || cfg.TriggerAllowedCIDRs != nil {
		t.Errorf("off by default: %v %q %v", cfg.TriggerAPI, cfg.TriggerTokenCredential, cfg.TriggerAllowedCIDRs)
	}
	t.Setenv("PREVIEWD_TRIGGER_API", "1")
	if cfg, err = Load(); err != nil || !cfg.TriggerAPI || cfg.TriggerTokenCredential != "trigger-token" {
		t.Fatalf("on: %+v, %v", cfg, err)
	}
	t.Setenv("PREVIEWD_TRIGGER_TOKEN_CREDENTIAL", "ci-token")
	t.Setenv("PREVIEWD_TRIGGER_ALLOWED_CIDRS", "10.40.0.0/16")
	if cfg, err = Load(); err != nil || cfg.TriggerTokenCredential != "ci-token" ||
		len(cfg.TriggerAllowedCIDRs) != 1 || cfg.TriggerAllowedCIDRs[0] != netip.MustParsePrefix("10.40.0.0/16") {
		t.Errorf("settings: %+v, %v", cfg, err)
	}
}

func TestLoadTriggerAPIFailsClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"opt-in true":           {"PREVIEWD_TRIGGER_API": "true"},
		"token in the env":      {"PREVIEWD_TRIGGER_API": "1", "PREVIEWD_TRIGGER_TOKEN": "do-not-print-0123456789abcdef0123456789"},
		"token in the env, off": {"PREVIEWD_TRIGGER_TOKEN": "do-not-print"},
		"credential as a path":  {"PREVIEWD_TRIGGER_API": "1", "PREVIEWD_TRIGGER_TOKEN_CREDENTIAL": "/etc/token"},
		"credential while off":  {"PREVIEWD_TRIGGER_TOKEN_CREDENTIAL": "trigger-token"},
		"cidrs while off":       {"PREVIEWD_TRIGGER_ALLOWED_CIDRS": "10.0.0.0/8"},
		"cidr with host bits":   {"PREVIEWD_TRIGGER_API": "1", "PREVIEWD_TRIGGER_ALLOWED_CIDRS": "10.0.0.1/8"},
		"cidr empty entry":      {"PREVIEWD_TRIGGER_API": "1", "PREVIEWD_TRIGGER_ALLOWED_CIDRS": "10.0.0.0/8,"},
	} {
		t.Run(name, func(t *testing.T) {
			minimalEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("%v accepted", env)
			}
			if strings.Contains(err.Error(), "do-not-print") {
				t.Errorf("the error quotes the token: %v", err)
			}
		})
	}
}
