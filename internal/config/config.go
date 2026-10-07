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
	RoutesDir           string
	TraefikContainer    string
	AllowTmpfsSecrets   bool
	AllowUnlockedMemory bool
	MaxConcurrentBuilds int
}

// defaultStagingDir mirrors secrets.DefaultStagingDir; config imports
// no internal package.
const defaultStagingDir = "/run/previewd/secrets"

// defaultRoutesDir is the directory Traefik's file provider watches
// (deployments/docker-compose.yml mounts it read-only).
const defaultRoutesDir = "/var/lib/previewd/routes"

// defaultTraefikContainer is the container_name in deployments/docker-compose.yml.
const defaultTraefikContainer = "traefik-proxy"

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
	if webhookSecret == "" {
		return nil, fmt.Errorf("PREVIEWD_WEBHOOK_SECRET is required: webhooks are never accepted unsigned")
	}

	secretsPath := os.Getenv("PREVIEWD_SECRETS_PATH")
	if secretsPath == "" {
		secretsPath = "secrets.env"
	}

	stagingDir := os.Getenv("PREVIEWD_SECRETS_STAGING_DIR")
	if stagingDir == "" {
		stagingDir = defaultStagingDir
	}

	routesDir := os.Getenv("PREVIEWD_ROUTES_DIR")
	if routesDir == "" {
		routesDir = defaultRoutesDir
	}

	traefikContainer := os.Getenv("PREVIEWD_TRAEFIK_CONTAINER")
	if traefikContainer == "" {
		traefikContainer = defaultTraefikContainer
	}

	allowTmpfs, err := optIn("PREVIEWD_ALLOW_TMPFS_SECRETS")
	if err != nil {
		return nil, err
	}
	allowUnlocked, err := optIn("PREVIEWD_ALLOW_UNLOCKED_MEMORY")
	if err != nil {
		return nil, err
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
		RoutesDir:           routesDir,
		TraefikContainer:    traefikContainer,
		AllowTmpfsSecrets:   allowTmpfs,
		AllowUnlockedMemory: allowUnlocked,
		MaxConcurrentBuilds: maxBuilds,
	}, nil
}

// optIn reads an opt-in flag. Opt-ins are exact: only "1" enables, any other
// non-empty value is a configuration error.
func optIn(name string) (bool, error) {
	switch v := os.Getenv(name); v {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("invalid %s %q: set exactly 1 or leave unset", name, v)
	}
}
