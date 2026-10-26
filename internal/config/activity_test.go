package config

import (
	"net/netip"
	"testing"
)

func TestLoadActivitySensing(t *testing.T) {
	minimalEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ActivitySensing || cfg.TraefikMetricsAddr != netip.MustParseAddrPort("172.30.255.2:8082") {
		t.Errorf("defaults: sensing %v, metrics %s; want on, the shipped entry point", cfg.ActivitySensing, cfg.TraefikMetricsAddr)
	}
	t.Setenv("PREVIEWD_ACTIVITY_SENSING", "0")
	t.Setenv("PREVIEWD_TRAEFIK_METRICS_ADDR", "[fd00::2]:9100")
	if cfg, err = Load(); err != nil || cfg.ActivitySensing || cfg.TraefikMetricsAddr != netip.MustParseAddrPort("[fd00::2]:9100") {
		t.Errorf("off, IPv6: %+v, %v", cfg, err)
	}
}

func TestLoadActivitySensingFailsClosed(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"sensing yes":       {"PREVIEWD_ACTIVITY_SENSING": "yes"},
		"sensing false":     {"PREVIEWD_ACTIVITY_SENSING": "false"},
		"metrics host name": {"PREVIEWD_TRAEFIK_METRICS_ADDR": "traefik:8082"},
		"metrics no port":   {"PREVIEWD_TRAEFIK_METRICS_ADDR": "172.30.255.2"},
		"metrics port 0":    {"PREVIEWD_TRAEFIK_METRICS_ADDR": "172.30.255.2:0"},
		"metrics any":       {"PREVIEWD_TRAEFIK_METRICS_ADDR": "0.0.0.0:8082"},
		"metrics zone":      {"PREVIEWD_TRAEFIK_METRICS_ADDR": "[fe80::1%eth0]:8082"},
		"metrics URL":       {"PREVIEWD_TRAEFIK_METRICS_ADDR": "http://172.30.255.2:8082/metrics"},
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
