package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config models all operational runtime flags for the sovereign daemon.
type Config struct {
	APIPort       int
	DBPath        string
	DockerHost    string
	TraefikDomain string
}

// Load extracts configuration from the host environment with strict fallback defaults.
func Load() (*Config, error) {
	apiPort := 8080
	if portStr := os.Getenv("PREVIEWD_API_PORT"); portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PREVIEWD_API_PORT: %w", err)
		}
		apiPort = p
	}

	dbPath := os.Getenv("PREVIEWD_DB_PATH")
	if dbPath == "" {
		dbPath = "previewd.sqlite"
	}

	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	traefikDomain := os.Getenv("PREVIEWD_TRAEFIK_DOMAIN")
	if traefikDomain == "" {
		traefikDomain = "local.previewd"
	}

	return &Config{
		APIPort:       apiPort,
		DBPath:        dbPath,
		DockerHost:    dockerHost,
		TraefikDomain: traefikDomain,
	}, nil
}
