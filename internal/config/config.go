package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config models all operational runtime flags for the sovereign daemon.
type Config struct {
	APIPort             int
	DBPath              string
	DockerHost          string
	TraefikDomain       string
	WebhookSecret       string
	SecretsPath         string
	SecretsStagingDir   string
	AllowTmpfsSecrets   bool
	MaxConcurrentBuilds int
}

// defaultStagingDir mirrors secrets.DefaultStagingDir; config imports
// no internal package.
const defaultStagingDir = "/run/previewd/secrets"

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

	webhookSecret := os.Getenv("PREVIEWD_WEBHOOK_SECRET")

	secretsPath := os.Getenv("PREVIEWD_SECRETS_PATH")
	if secretsPath == "" {
		secretsPath = "secrets.env"
	}

	stagingDir := os.Getenv("PREVIEWD_SECRETS_STAGING_DIR")
	if stagingDir == "" {
		stagingDir = defaultStagingDir
	}

	// Opt-ins are exact: only "1" enables, any other non-empty value is an error.
	allowTmpfs := false
	switch v := os.Getenv("PREVIEWD_ALLOW_TMPFS_SECRETS"); v {
	case "":
	case "1":
		allowTmpfs = true
	default:
		return nil, fmt.Errorf("invalid PREVIEWD_ALLOW_TMPFS_SECRETS %q: set exactly 1 or leave unset", v)
	}

	maxBuilds := 2
	if mbStr := os.Getenv("PREVIEWD_MAX_BUILDS"); mbStr != "" {
		if mb, err := strconv.Atoi(mbStr); err == nil && mb > 0 {
			maxBuilds = mb
		}
	}

	return &Config{
		APIPort:             apiPort,
		DBPath:              dbPath,
		DockerHost:          dockerHost,
		TraefikDomain:       traefikDomain,
		WebhookSecret:       webhookSecret,
		SecretsPath:         secretsPath,
		SecretsStagingDir:   stagingDir,
		AllowTmpfsSecrets:   allowTmpfs,
		MaxConcurrentBuilds: maxBuilds,
	}, nil
}
