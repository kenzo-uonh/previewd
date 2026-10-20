package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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
	// Workers is PREVIEWD_MAX_BUILDS: reconciler workers, jobs run at once.
	Workers            int
	ContainerMemoryMiB int64
	ContainerPids      int64

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

	// Build isolation (V1 F2). AllowedBaseImages holds canonical
	// name@sha256:<hex> references (validate.AllowedBaseImages); a FROM
	// outside it is refused before any build request.
	AllowedBaseImages    map[string]bool
	MaxBuildContextBytes int64
	// BuildKitCgroup is the cgroup v2 subtree bounding BuildKit RUN steps
	// (D-V1-4), verified at every start; AllowUnboundedBuilds is the opt-in
	// that skips that verification (dev hosts, cgroup v1). Exactly one is set.
	BuildKitCgroup       string
	AllowUnboundedBuilds bool
	// BuildProbeAddr is the startup probe's TCP target; the zero value means
	// the default bridge gateway, port 9.
	BuildProbeAddr netip.AddrPort
	// MaxConcurrentBuilds bounds the builds in flight across all workers:
	// they share the daemon-level BuildKit limits (D-V1-4). BuildTimeout
	// cancels a build request; the deploy then fails (failure = 'build').
	MaxConcurrentBuilds int
	BuildTimeout        time.Duration

	// Database maintenance (V1 F3): Prune every PruneInterval, in
	// transactions of at most PruneBatch rows, what is older than Retention.
	Retention     time.Duration
	PruneInterval time.Duration
	PruneBatch    int

	// Auto-cleanup (V1 F5). EnvTTL is 0 when PREVIEWD_ENV_TTL=0 disables
	// the TTL. A build starts only with MinFreeDiskBytes free on the file
	// system of DockerDataRoot ("" for the daemon's DockerRootDir).
	EnvTTL time.Duration
	// Developer feedback (V1.1 spec 3.3): the commit status and sticky comment
	// of each deploy. Feedback is PREVIEWD_FEEDBACK (on unless exactly 0);
	// PreviewScheme is the scheme of the preview URL in them,
	// PREVIEWD_PREVIEW_URL_SCHEME (http or https, default http: the shipped
	// Traefik entrypoint serves plain HTTP).
	Feedback         bool
	PreviewScheme    string
	MinFreeDiskBytes int64
	DockerDataRoot   string

	// WebhookSecretCredential names the systemd credential holding the
	// webhook HMAC secret: read from $CREDENTIALS_DIRECTORY, never from the
	// environment or a configured path.
	WebhookSecretCredential string

	// VCSProvider is PREVIEWD_VCS_PROVIDER: the one forge the daemon serves,
	// "github" (the default: GHES and github.com) or "gitlab" (V1.1 spec 3.1).
	// Approvers and FullSecretsRepos name projects as that forge spells them.
	VCSProvider string

	// GHES (V1 F4, C3): read as a GitHub App. The key is a systemd
	// credential name, never a path. Set for the github provider only.
	GHESURL                string // https://host[:port]
	GHESCAFile             string // site CA bundle; "" for the system roots
	GitHubAppID            int64
	GitHubAppKeyCredential string

	// GitLab (V1.1 spec 3.1), for the gitlab provider only: the access token
	// and the webhook's shared secret are systemd credential names, never
	// paths and never values. WebhookSecretCredential is then the latter.
	GitLabURL                     string // https://host[:port]
	GitLabCAFile                  string // site CA bundle; "" for the system roots
	GitLabTokenCredential         string
	GitLabWebhookSecretCredential string

	// Webhook listener (V1 F4, C2). TLS unless AllowPlaintextWebhooks.
	TLSCertFile            string
	TLSKeyCredential       string
	AllowPlaintextWebhooks bool
	WebhookAllowedCIDRs    []netip.Prefix
}

const (
	defaultAppKeyCredential        = "github-app-key"        // #nosec G101 -- the name of a systemd credential, not a credential
	defaultWebhookSecretCredential = "webhook_secret"        // #nosec G101 -- the name of a systemd credential, not a credential
	defaultGitLabTokenCredential   = "gitlab-api-token"      // #nosec G101 -- the name of a systemd credential, not a credential
	defaultGitLabHookCredential    = "gitlab-webhook-secret" // #nosec G101 -- the name of a systemd credential, not a credential
	// legacyWebhookSecretEnv held the secret itself before V1: refused.
	legacyWebhookSecretEnv    = "PREVIEWD_WEBHOOK_SECRET"        // #nosec G101 -- an environment variable name, not a credential
	legacyGitLabTokenEnv      = "PREVIEWD_GITLAB_TOKEN"          // #nosec G101 -- an environment variable name, not a credential
	legacyGitLabHookEnv       = "PREVIEWD_GITLAB_WEBHOOK_SECRET" // #nosec G101 -- an environment variable name, not a credential
	defaultApprovalLabel      = "previewd-approved"
	defaultDeliveryMaxAge     = 15 * time.Minute
	minDeliveryMaxAge         = time.Minute
	maxDeliveryMaxAge         = 2 * time.Hour
	defaultRevalidateInterval = 10 * time.Minute
	defaultRevalidateGrace    = time.Hour
	maxRevalidateGrace        = 24 * time.Hour
	defaultMaxBuildContextMiB = 512
	maxBuildContextMiB        = 16384
	defaultWorkers            = 2
	maxWorkers                = 64
	defaultConcurrentBuilds   = 1
	maxConcurrentBuilds       = 16
	defaultBuildTimeout       = 20 * time.Minute
	minBuildTimeout           = time.Minute
	maxBuildTimeout           = 2 * time.Hour
	defaultRetention          = 720 * time.Hour
	minRetention              = 24 * time.Hour
	maxRetention              = 10 * 8760 * time.Hour
	defaultPruneInterval      = time.Hour
	maxPruneInterval          = 24 * time.Hour
	defaultPruneBatch         = 500
	minPruneBatch             = 10
	maxPruneBatch             = 10000
	defaultEnvTTL             = 168 * time.Hour
	maxEnvTTL                 = 10 * 8760 * time.Hour
	defaultMinFreeDiskMiB     = 10240
	minMinFreeDiskMiB         = 1024
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

	dbPath := DBPath()

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
	for _, name := range []string{legacyGitLabTokenEnv, legacyGitLabHookEnv} {
		if _, set := os.LookupEnv(name); set {
			return nil, fmt.Errorf("%s is set: a GitLab secret is never read from the environment; "+
				"remove it and pass it as the systemd credential named by %s_CREDENTIAL", name, name)
		}
	}
	provider, err := vcsProvider()
	if err != nil {
		return nil, err
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

	workers, err := boundedCount("PREVIEWD_MAX_BUILDS", defaultWorkers, 1, maxWorkers)
	if err != nil {
		return nil, err
	}

	memoryMiB, err := positiveInt("PREVIEWD_CONTAINER_MEMORY_MIB", 512)
	if err != nil {
		return nil, err
	}
	pids, err := positiveInt("PREVIEWD_CONTAINER_PIDS", 256)
	if err != nil {
		return nil, err
	}

	parseApprovers, repoValid := validate.ParseApprovers, validate.RepoFullName
	if provider == providerGitLab {
		parseApprovers, repoValid = validate.ParseGitLabApprovers, validate.GitLabProjectPath
	}
	approvers, err := parseApprovers(os.Getenv("PREVIEWD_APPROVERS"))
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

	fullSecrets, err := repoSet("PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS", repoValid)
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

	allowedBases, err := validate.AllowedBaseImages(os.Getenv("PREVIEWD_ALLOWED_BASE_IMAGES"))
	if err != nil {
		return nil, fmt.Errorf("PREVIEWD_ALLOWED_BASE_IMAGES is required: %w", err)
	}
	contextMiB, err := boundedInt("PREVIEWD_MAX_BUILD_CONTEXT_MIB", defaultMaxBuildContextMiB, 1, maxBuildContextMiB)
	if err != nil {
		return nil, err
	}

	buildkitCgroup := os.Getenv("PREVIEWD_BUILDKIT_CGROUP")
	unbounded, err := optIn("PREVIEWD_ALLOW_UNBOUNDED_BUILDS")
	if err != nil {
		return nil, err
	}
	switch {
	case unbounded && buildkitCgroup != "":
		return nil, fmt.Errorf("PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1 contradicts PREVIEWD_BUILDKIT_CGROUP: set one or the other")
	case !unbounded && buildkitCgroup == "":
		return nil, fmt.Errorf("PREVIEWD_BUILDKIT_CGROUP is required: the cgroup v2 subtree bounding BuildKit builds (or set PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1)")
	case buildkitCgroup != "" && (buildkitCgroup != filepath.Clean(buildkitCgroup) || !strings.HasPrefix(buildkitCgroup, "/sys/fs/cgroup/")):
		return nil, fmt.Errorf("invalid PREVIEWD_BUILDKIT_CGROUP %q: want a clean absolute path under /sys/fs/cgroup", buildkitCgroup)
	}
	var probeAddr netip.AddrPort
	if v := os.Getenv("PREVIEWD_BUILD_PROBE_ADDR"); v != "" {
		if probeAddr, err = netip.ParseAddrPort(v); err != nil || probeAddr.Port() == 0 || probeAddr.Addr().IsUnspecified() || probeAddr.Addr().Zone() != "" {
			return nil, fmt.Errorf("invalid PREVIEWD_BUILD_PROBE_ADDR %q: want IP:PORT, an IP literal and a non-zero port", v)
		}
	}

	concurrentBuilds, err := boundedCount("PREVIEWD_MAX_CONCURRENT_BUILDS", defaultConcurrentBuilds, 1, maxConcurrentBuilds)
	if err != nil {
		return nil, err
	}
	buildTimeout, err := boundedDuration("PREVIEWD_BUILD_TIMEOUT", defaultBuildTimeout, minBuildTimeout, maxBuildTimeout)
	if err != nil {
		return nil, err
	}
	retention, err := boundedDuration("PREVIEWD_RETENTION", defaultRetention, minRetention, maxRetention)
	if err != nil {
		return nil, err
	}
	pruneInterval, err := boundedDuration("PREVIEWD_PRUNE_INTERVAL", defaultPruneInterval, minPruneInterval, maxPruneInterval)
	if err != nil {
		return nil, err
	}
	pruneBatch, err := boundedCount("PREVIEWD_PRUNE_BATCH", defaultPruneBatch, minPruneBatch, maxPruneBatch)
	if err != nil {
		return nil, err
	}
	envTTL := time.Duration(0)
	feedback, err := feedbackSwitch()
	if err != nil {
		return nil, err
	}
	previewScheme, err := previewScheme()
	if err != nil {
		return nil, err
	}
	if os.Getenv("PREVIEWD_ENV_TTL") != "0" {
		if envTTL, err = boundedDuration("PREVIEWD_ENV_TTL", defaultEnvTTL, minEnvTTL, maxEnvTTL); err != nil {
			return nil, fmt.Errorf("%w (or 0 to disable)", err)
		}
	}
	minFreeDiskMiB, err := boundedInt("PREVIEWD_MIN_FREE_DISK_MIB", defaultMinFreeDiskMiB, minMinFreeDiskMiB, maxPositiveInt)
	if err != nil {
		return nil, err
	}
	dataRoot := os.Getenv("PREVIEWD_DOCKER_DATA_ROOT")
	if dataRoot != "" && (!filepath.IsAbs(dataRoot) || dataRoot != filepath.Clean(dataRoot)) {
		return nil, fmt.Errorf("invalid PREVIEWD_DOCKER_DATA_ROOT %q: want a clean absolute path", dataRoot)
	}

	forge, err := loadForge(provider)
	if err != nil {
		return nil, err
	}
	if provider == providerGitLab && labelApproval {
		// The label path is GitHub's: a GitLab approval is an approval event.
		return nil, errors.New("PREVIEWD_LABEL_APPROVAL is not supported with PREVIEWD_VCS_PROVIDER=gitlab: a GitLab merge request is approved with GitLab's own approval")
	}
	if provider == providerGitLab {
		if _, set := os.LookupEnv("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL"); set {
			return nil, fmt.Errorf("PREVIEWD_WEBHOOK_SECRET_CREDENTIAL contradicts PREVIEWD_VCS_PROVIDER=gitlab: " +
				"the webhook secret is the credential named by PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL")
		}
		webhookSecretCred = forge.gitlabHookCredential
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
		Workers:             workers,
		ContainerMemoryMiB:  memoryMiB,
		ContainerPids:       pids,
		Approvers:           approvers,
		LabelApproval:       labelApproval,
		ApprovalLabel:       approvalLabel,
		DeliveryMaxAge:      maxAge,
		FullSecretsRepos:    fullSecrets,
		RevalidateInterval:  revalInterval,
		RevalidateGrace:     revalGrace,

		AllowedBaseImages:    allowedBases,
		MaxBuildContextBytes: contextMiB << 20,
		BuildKitCgroup:       buildkitCgroup,
		AllowUnboundedBuilds: unbounded,
		BuildProbeAddr:       probeAddr,
		MaxConcurrentBuilds:  concurrentBuilds,
		BuildTimeout:         buildTimeout,

		Retention:     retention,
		PruneInterval: pruneInterval,
		PruneBatch:    pruneBatch,

		EnvTTL:           envTTL,
		Feedback:         feedback,
		PreviewScheme:    previewScheme,
		MinFreeDiskBytes: minFreeDiskMiB << 20,
		DockerDataRoot:   dataRoot,

		WebhookSecretCredential: webhookSecretCred,
		VCSProvider:             provider,
		GHESURL:                 forge.ghesURL,
		GHESCAFile:              forge.ghesCAFile,
		GitHubAppID:             forge.appID,
		GitHubAppKeyCredential:  forge.appKey,

		GitLabURL:                     forge.gitlabURL,
		GitLabCAFile:                  forge.gitlabCAFile,
		GitLabTokenCredential:         forge.gitlabTokenCredential,
		GitLabWebhookSecretCredential: forge.gitlabHookCredential,
		TLSCertFile:                   certFile,
		TLSKeyCredential:              keyCred,
		AllowPlaintextWebhooks:        plaintext,
		WebhookAllowedCIDRs:           cidrs,
	}, nil
}

// DBPath is PREVIEWD_DB_PATH, previewd.sqlite when unset. The audit
// subcommands read it without the daemon's other keys.
func DBPath() string {
	if p := os.Getenv("PREVIEWD_DB_PATH"); p != "" {
		return p
	}
	return "previewd.sqlite"
}

// repoSet reads a comma-separated owner/repo list. Unset or empty is the
// empty set; an empty entry, an invalid name or a repository listed twice
// is a configuration error.
func repoSet(name string, valid func(string) error) (map[string]bool, error) {
	out := map[string]bool{}
	v := os.Getenv(name)
	if v == "" {
		return out, nil
	}
	for i, repo := range strings.Split(v, ",") {
		if err := valid(repo); err != nil {
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

// boundedInt reads an integer. Unset means def; anything but an integer in
// [lo, hi] is a configuration error.
func boundedInt(name string, def, lo, hi int64) (int64, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("invalid %s %q: want an integer in %d..%d", name, v, lo, hi)
	}
	return n, nil
}

// boundedCount reads a count kept as an int (workers, slots, batch size).
// It parses at the platform's int size, so no value is ever narrowed: an
// integer outside [lo, hi], including one that does not fit an int, is a
// configuration error.
func boundedCount(name string, def, lo, hi int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("invalid %s %q: want an integer in %d..%d", name, v, lo, hi)
	}
	return n, nil
}

// optIn reads an opt-in flag. Opt-ins are exact: only "1" enables, any other
// non-empty value is a configuration error.
// feedbackSwitch reads PREVIEWD_FEEDBACK: on when unset or 1, off when
// exactly 0, an error otherwise.
func feedbackSwitch() (bool, error) {
	switch v := os.Getenv("PREVIEWD_FEEDBACK"); v {
	case "", "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid PREVIEWD_FEEDBACK %q: set exactly 0 or 1, or leave unset", v)
	}
}

// previewScheme reads PREVIEWD_PREVIEW_URL_SCHEME: http (default) or https.
func previewScheme() (string, error) {
	switch v := os.Getenv("PREVIEWD_PREVIEW_URL_SCHEME"); v {
	case "", "http":
		return "http", nil
	case "https":
		return "https", nil
	default:
		return "", fmt.Errorf("invalid PREVIEWD_PREVIEW_URL_SCHEME %q: set http or https, or leave unset", v)
	}
}

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
