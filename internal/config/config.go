package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// Config models all operational runtime flags for the sovereign daemon.
type Config struct {
	APIPort             int
	DBPath              string
	DockerHost          string
	TraefikDomain       string
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
	// FullSecretsRepos is the D-V1-1 opt-in: approved untrusted deploys of
	// these repositories get the trusted secret section.
	FullSecretsRepos map[string]bool
	// Re-validation of running environments (D-V1-5, V1-I4).
	RevalidateInterval time.Duration
	RevalidateGrace    time.Duration

	// WebhookSecretCredential names the systemd credential holding the
	// webhook HMAC secret: read from $CREDENTIALS_DIRECTORY, never from the
	// environment or a configured path.
	WebhookSecretCredential string

	// GHES (V1 F4, C3): read as a GitHub App. The key is a systemd
	// credential name, never a path.
	GHESURL                string // https://host[:port]
	GHESCAFile             string // site CA bundle; "" for the system roots
	GitHubAppID            int64
	GitHubAppKeyCredential string

	// Webhook listener (V1 F4, C2). TLS unless AllowPlaintextWebhooks.
	TLSCertFile            string
	TLSKeyCredential       string
	AllowPlaintextWebhooks bool
	WebhookAllowedCIDRs    []netip.Prefix
}

const (
	defaultAppKeyCredential        = "github-app-key" // #nosec G101 -- the name of a systemd credential, not a credential
	defaultWebhookSecretCredential = "webhook_secret" // #nosec G101 -- the name of a systemd credential, not a credential
	// legacyWebhookSecretEnv held the secret itself before V1: refused.
	legacyWebhookSecretEnv    = "PREVIEWD_WEBHOOK_SECRET" // #nosec G101 -- an environment variable name, not a credential
	defaultApprovalLabel      = "previewd-approved"
	defaultDeliveryMaxAge     = 15 * time.Minute
	minDeliveryMaxAge         = time.Minute
	maxDeliveryMaxAge         = 2 * time.Hour
	defaultRevalidateInterval = 10 * time.Minute
	defaultRevalidateGrace    = time.Hour
	maxRevalidateGrace        = 24 * time.Hour
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

	// Zero secrets in the environment: a secret there is readable in
	// /proc/<pid>/environ, inherited by children and kept in unit files.
	// Its value is never read; its presence refuses to start, so it is
	// never left in place believed to be in use.
	if _, set := os.LookupEnv(legacyWebhookSecretEnv); set {
		return nil, fmt.Errorf("%s is set: the webhook secret is never read from the environment; "+
			"remove it and pass the secret as the systemd credential named by PREVIEWD_WEBHOOK_SECRET_CREDENTIAL (default %s)",
			legacyWebhookSecretEnv, defaultWebhookSecretCredential)
	}
	webhookSecretCred, err := credentialName("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL", defaultWebhookSecretCredential)
	if err != nil {
		return nil, err
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

	fullSecrets, err := repoSet("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS")
	if err != nil {
		return nil, err
	}
	revalInterval, err := boundedDuration("PREVIEWD_APPROVAL_REVALIDATE_INTERVAL", defaultRevalidateInterval, time.Minute, time.Hour)
	if err != nil {
		return nil, err
	}
	revalGrace, err := boundedDuration("PREVIEWD_APPROVAL_REVALIDATE_GRACE", max(defaultRevalidateGrace, revalInterval), revalInterval, maxRevalidateGrace)
	if err != nil {
		return nil, err
	}

	ghesURL, err := validate.GHESURL(os.Getenv("PREVIEWD_GHES_URL"))
	if err != nil {
		return nil, fmt.Errorf("PREVIEWD_GHES_URL is required: %w", err)
	}
	appID, err := strconv.ParseInt(os.Getenv("PREVIEWD_GITHUB_APP_ID"), 10, 64)
	if err != nil || appID < 1 {
		return nil, fmt.Errorf("PREVIEWD_GITHUB_APP_ID is required: a positive integer")
	}
	appKey, err := credentialName("PREVIEWD_GITHUB_APP_KEY_CREDENTIAL", defaultAppKeyCredential)
	if err != nil {
		return nil, err
	}
	plaintext, err := optIn("PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS")
	if err != nil {
		return nil, err
	}
	certFile, keyCred := os.Getenv("PREVIEWD_TLS_CERT_FILE"), os.Getenv("PREVIEWD_TLS_KEY_CREDENTIAL")
	switch {
	case plaintext && (certFile != "" || keyCred != ""):
		return nil, fmt.Errorf("PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS=1 contradicts PREVIEWD_TLS_CERT_FILE and PREVIEWD_TLS_KEY_CREDENTIAL: set one or the other")
	case !plaintext && (certFile == "" || keyCred == ""):
		return nil, fmt.Errorf("PREVIEWD_TLS_CERT_FILE and PREVIEWD_TLS_KEY_CREDENTIAL are required: webhooks arrive over TLS (or set PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS=1)")
	case keyCred != "":
		if err := validate.CredentialName(keyCred); err != nil {
			return nil, fmt.Errorf("invalid PREVIEWD_TLS_KEY_CREDENTIAL: %w", err)
		}
	}
	cidrs, err := validate.CIDRs(os.Getenv("PREVIEWD_WEBHOOK_ALLOWED_CIDRS"))
	if err != nil {
		return nil, fmt.Errorf("invalid PREVIEWD_WEBHOOK_ALLOWED_CIDRS: %w", err)
	}

	return &Config{
		APIPort:             apiPort,
		DBPath:              dbPath,
		DockerHost:          dockerHost,
		TraefikDomain:       traefikDomain,
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
		FullSecretsRepos:    fullSecrets,
		RevalidateInterval:  revalInterval,
		RevalidateGrace:     revalGrace,

		WebhookSecretCredential: webhookSecretCred,
		GHESURL:                 ghesURL,
		GHESCAFile:              os.Getenv("PREVIEWD_GHES_CA_FILE"),
		GitHubAppID:             appID,
		GitHubAppKeyCredential:  appKey,
		TLSCertFile:             certFile,
		TLSKeyCredential:        keyCred,
		AllowPlaintextWebhooks:  plaintext,
		WebhookAllowedCIDRs:     cidrs,
	}, nil
}

// repoSet reads a comma-separated owner/repo list. Unset or empty is the
// empty set; an empty entry, an invalid name or a repository listed twice
// is a configuration error.
func repoSet(name string) (map[string]bool, error) {
	out := map[string]bool{}
	v := os.Getenv(name)
	if v == "" {
		return out, nil
	}
	for i, repo := range strings.Split(v, ",") {
		if err := validate.RepoFullName(repo); err != nil {
			return nil, fmt.Errorf("invalid %s entry %d: %w", name, i+1, err)
		}
		if out[repo] {
			return nil, fmt.Errorf("invalid %s: %s listed twice", name, repo)
		}
		out[repo] = true
	}
	return out, nil
}

// credentialName reads a systemd credential name, def when unset.
func credentialName(name, def string) (string, error) {
	v, set := os.LookupEnv(name)
	if !set {
		return def, nil
	}
	if err := validate.CredentialName(v); err != nil {
		return "", fmt.Errorf("invalid %s: %w", name, err)
	}
	return v, nil
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
