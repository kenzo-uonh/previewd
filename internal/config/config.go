package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kenzo-uonh/previewd/internal/validate"
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
	ContainerMemoryMiB  int64
	ContainerPids       int64

	// Approval gating (V1 F1). Approvers maps owner/repo, as GitHub spells
	// it, to the accounts whose review or label approves untrusted code.
	Approvers      map[string][]validate.Approver
	LabelApproval  bool   // PREVIEWD_LABEL_APPROVAL opt-in
	ApprovalLabel  string // the label that approves when LabelApproval is set
	DeliveryMaxAge time.Duration
}

const (
	defaultApprovalLabel  = "previewd-approved"
	defaultDeliveryMaxAge = 15 * time.Minute
	minDeliveryMaxAge     = time.Minute
	maxDeliveryMaxAge     = 2 * time.Hour
)

// defaultStagingDir mirrors secrets.DefaultStagingDir; config imports
// no internal package but the validate leaf.
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

	memoryMiB, err := positiveInt("PREVIEWD_CONTAINER_MEMORY_MIB", 512)
	if err != nil {
		return nil, err
	}
	pids, err := positiveInt("PREVIEWD_CONTAINER_PIDS", 256)
	if err != nil {
		return nil, err
	}

	approvers, err := validate.ParseApprovers(os.Getenv("PREVIEWD_APPROVERS"))
	if err != nil {
		return nil, fmt.Errorf("invalid PREVIEWD_APPROVERS: %w", err)
	}
	labelApproval, err := optIn("PREVIEWD_LABEL_APPROVAL")
	if err != nil {
		return nil, err
	}
	approvalLabel := defaultApprovalLabel
	if v, set := os.LookupEnv("PREVIEWD_APPROVAL_LABEL"); set {
		if err := validate.LabelName(v); err != nil {
			return nil, fmt.Errorf("invalid PREVIEWD_APPROVAL_LABEL: %w", err)
		}
		approvalLabel = v
	}
	maxAge, err := boundedDuration("PREVIEWD_DELIVERY_MAX_AGE", defaultDeliveryMaxAge, minDeliveryMaxAge, maxDeliveryMaxAge)
	if err != nil {
		return nil, err
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
		ContainerMemoryMiB:  memoryMiB,
		ContainerPids:       pids,
		Approvers:           approvers,
		LabelApproval:       labelApproval,
		ApprovalLabel:       approvalLabel,
		DeliveryMaxAge:      maxAge,
	}, nil
}

// boundedDuration reads a Go duration. Unset means def; anything outside
// [lo, hi], or not a duration, is a configuration error.
func boundedDuration(name string, def, lo, hi time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < lo || d > hi {
		return 0, fmt.Errorf("invalid %s %q: want a duration in %s..%s", name, v, lo, hi)
	}
	return d, nil
}

// maxPositiveInt keeps a MiB value convertible to bytes in an int64.
const maxPositiveInt = 1 << 40

// positiveInt reads a limit. Unset means def; anything but an integer in
// 1..2^40 is a configuration error, never a silent fallback.
func positiveInt(name string, def int64) (int64, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 || n > maxPositiveInt {
		return 0, fmt.Errorf("invalid %s %q: want an integer in 1..%d", name, v, int64(maxPositiveInt))
	}
	return n, nil
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
