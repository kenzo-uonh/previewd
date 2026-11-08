package main

// previewd doctor (V1.1 spec, Day-2): the host's readiness for the daemon,
// checked before it runs. Every check stands on its own and every one runs,
// so the operator sees all the problems at once. A control that cannot be
// verified fails; the doctor never warns. It changes nothing on the host
// and needs no credential.

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/hardening"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
	"github.com/kenzo-uonh/previewd/internal/secrets"
	"github.com/kenzo-uonh/previewd/internal/textutil"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

const (
	// defaultConfFile is the unit's EnvironmentFile= (previewd.service).
	defaultConfFile = "/etc/previewd/previewd.conf"
	// maxConfBytes bounds the conf file.
	maxConfBytes = 1 << 20
	// doctorTimeout bounds the whole run; forgeTimeout one request to the forge.
	doctorTimeout = 2 * time.Minute
	forgeTimeout  = 15 * time.Second
	// maxReportBytes bounds the text of one check's verdict.
	maxReportBytes = 400
	// serviceUser is the account the unit runs as.
	serviceUser = "previewd"
	// The units whose properties the doctor reads.
	dockerUnit   = "docker.service"
	previewdUnit = "previewd.service"
)

// exitChecksFailed is the doctor's exit code when any check failed.
const exitChecksFailed = exitBroken

const doctorUsage = `usage:
  previewd doctor [-conf PATH] [-user NAME]
      Check that this host is ready to run the daemon, then exit 0 if every
      check passed and 1 if any failed (2 on bad arguments):
        build cgroup       cgroup v2 build slice: finite memory.max, pids.max
                           and cpu.max, memory.swap.max 0
        dockerd egress     docker.service denies all IP traffic but loopback,
                           the proxy network and the site mirror
        secrets staging    a ramfs mount, mode 0700, owned by NAME
        memory lock        previewd.service has LimitMEMLOCK=infinity and the
                           kernel lets a process mlockall
        clock skew         the forge's Date header is within 2 s of this host
        traefik isolation  the proxy container has no Docker socket
      Settings come from PATH (default ` + defaultConfFile + `, the unit's
      EnvironmentFile; PREVIEWD_* keys only), then the environment, then the
      daemon's defaults. NAME defaults to ` + serviceUser + `. Run as root, or
      as a member of the docker group that can run systemctl show.
`

// doctorHost is everything the doctor asks of the machine. Tests supply
// their own; newDoctorHost is the real one.
type doctorHost struct {
	readFile     func(path string, limit int64) ([]byte, error)
	buildCgroup  func(dir string) error
	dockerEgress func(ctx context.Context) error
	stagingMount func(dir string, uid int) error
	lookupUID    func(name string) (int, error)
	unitMemlock  func(ctx context.Context) error
	mlockall     func() error
	// clockSkew returns the forge's clock minus this host's, and an error
	// when it is not within the limit or could not be read.
	clockSkew func(ctx context.Context, rawURL string, caPEM []byte) (time.Duration, error)
	proxy     func(ctx context.Context, container string) error
}

func newDoctorHost() doctorHost {
	return doctorHost{
		readFile: readBounded,
		buildCgroup: func(dir string) error {
			cg, err := hardening.NewBuildCgroup(dir)
			if err != nil {
				return err
			}
			return cg.CheckLimits()
		},
		dockerEgress: func(ctx context.Context) error {
			return hardening.CheckUnitEgress(ctx, hardening.SystemctlShow, dockerUnit)
		},
		stagingMount: hardening.CheckStagingMount,
		lookupUID: func(name string) (int, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, err
			}
			uid, err := strconv.Atoi(u.Uid)
			if err != nil {
				return 0, fmt.Errorf("user %s: uid %q: %w", name, u.Uid, err)
			}
			return uid, nil
		},
		unitMemlock: func(ctx context.Context) error {
			return hardening.CheckUnitMemlock(ctx, hardening.SystemctlShow, previewdUnit)
		},
		mlockall:  hardening.ProbeMlockall,
		clockSkew: probeForgeClock,
		proxy:     verifyProxy,
	}
}

// probeForgeClock asks the forge at rawURL for its clock, over TLS 1.2 or
// later against the site CA bundle (the system roots when nil) and with no
// proxy from the environment, as the daemon's clients do.
func probeForgeClock(ctx context.Context, rawURL string, caPEM []byte) (time.Duration, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != nil {
		pool, err := vcs.CertPool(caPEM)
		if err != nil {
			return 0, fmt.Errorf("%w: CA bundle: %w", hardening.ErrClockSkew, err)
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: forgeTimeout}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: forgeTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: forgeTimeout}
	return hardening.ProbeClockSkew(ctx, client, rawURL, time.Now)
}

// verifyProxy runs the daemon's own proxy check (orchestrator.VerifyProxy):
// a running, unprivileged Traefik without a mounted socket or a Docker
// provider. The engine is built only to ask Docker; its limits are unused.
func verifyProxy(ctx context.Context, container string) (err error) {
	engine, err := orchestrator.NewDockerEngine(container, orchestrator.Limits{MemoryBytes: 1 << 20, Pids: 1}, "", hardening.FreeDiskBytes)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := engine.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close docker client: %w", closeErr))
		}
	}()
	return engine.VerifyProxy(ctx)
}

// doctorRun is one run: where its settings come from, and the host.
type doctorRun struct {
	host    doctorHost
	setting func(key string) string
	user    string
}

type doctorCheck struct {
	name string
	run  func(ctx context.Context) (detail string, err error)
}

// runDoctor is `previewd doctor`. getenv is os.Getenv in production.
func runDoctor(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, host doctorHost) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := doctorCommand(ctx, args, getenv, host, out, diag)
	if code != exitUsage && out.err != nil {
		diag.printf("previewd doctor: write the report: %v\n", out.err)
		return exitUsage
	}
	return code
}

func doctorCommand(ctx context.Context, args []string, getenv func(string) string, host doctorHost, out, diag *console) int {
	flags := flag.NewFlagSet("previewd doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	conf := flags.String("conf", defaultConfFile, "")
	account := flags.String("user", serviceUser, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *conf == "" || *account == "" {
		diag.printf("previewd doctor: invalid arguments\n%s", doctorUsage)
		return exitUsage
	}
	explicit := false
	flags.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "conf" })

	fileSettings := map[string]string{}
	switch data, err := host.readFile(*conf, maxConfBytes); {
	case err == nil:
		if fileSettings, err = parseConf(data); err != nil {
			diag.printf("previewd doctor: %s: %v\n", *conf, err)
			return exitUsage
		}
	case !explicit && errors.Is(err, fs.ErrNotExist):
		// No site file: the environment and the defaults decide.
	default:
		diag.printf("previewd doctor: read %s: %v\n", *conf, err)
		return exitUsage
	}

	run := &doctorRun{
		host: host,
		user: *account,
		setting: func(key string) string {
			if v, ok := fileSettings[key]; ok {
				return v
			}
			return getenv(key)
		},
	}
	ctx, cancel := context.WithTimeout(ctx, doctorTimeout)
	defer cancel()

	out.printf("previewd doctor\n")
	passed := 0
	checks := run.checks()
	for _, c := range checks {
		detail, err := c.run(ctx)
		if err != nil {
			out.printf("[FAIL] %s: %s\n", c.name, oneLine(err.Error()))
			continue
		}
		passed++
		out.printf("[PASS] %s: %s\n", c.name, oneLine(detail))
	}
	out.printf("%d of %d checks passed\n", passed, len(checks))
	if passed != len(checks) {
		return exitChecksFailed
	}
	return exitOK
}

func (r *doctorRun) checks() []doctorCheck {
	return []doctorCheck{
		{"build cgroup", r.checkBuildCgroup},
		{"dockerd egress", r.checkDockerEgress},
		{"secrets staging", r.checkSecretsStaging},
		{"memory lock", r.checkMemoryLock},
		{"clock skew", r.checkClockSkew},
		{"traefik isolation", r.checkTraefik},
	}
}

// valueOr is setting key, def when it is empty.
func (r *doctorRun) valueOr(key, def string) string {
	if v := r.setting(key); v != "" {
		return v
	}
	return def
}

func (r *doctorRun) checkBuildCgroup(context.Context) (string, error) {
	dir := r.valueOr("PREVIEWD_BUILDKIT_CGROUP", config.DefaultBuildCgroup)
	if dir != filepath.Clean(dir) || !strings.HasPrefix(dir, "/sys/fs/cgroup/") {
		return "", fmt.Errorf("PREVIEWD_BUILDKIT_CGROUP %s: want a clean absolute path under /sys/fs/cgroup", validate.Quote(dir))
	}
	if err := r.host.buildCgroup(dir); err != nil {
		return "", err
	}
	return dir + ": cgroup v2; memory.max, pids.max and the cpu.max quota finite; memory.swap.max 0", nil
}

func (r *doctorRun) checkDockerEgress(ctx context.Context) (string, error) {
	if err := r.host.dockerEgress(ctx); err != nil {
		return "", err
	}
	return dockerUnit + ": IPAddressDeny covers IPv4 and IPv6, no allow-list entry re-opens it, files loaded", nil
}

func (r *doctorRun) checkSecretsStaging(context.Context) (string, error) {
	dir := r.valueOr("PREVIEWD_SECRETS_STAGING_DIR", secrets.DefaultStagingDir)
	if !filepath.IsAbs(dir) || dir != filepath.Clean(dir) {
		return "", fmt.Errorf("PREVIEWD_SECRETS_STAGING_DIR %s: want a clean absolute path", validate.Quote(dir))
	}
	uid, err := r.host.lookupUID(r.user)
	if err != nil {
		return "", fmt.Errorf("service user %s: %w", validate.Quote(r.user), err)
	}
	if err := r.host.stagingMount(dir, uid); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: ramfs mount point, mode 0700, owned by %s (uid %d)", dir, r.user, uid), nil
}

func (r *doctorRun) checkMemoryLock(ctx context.Context) (string, error) {
	if err := r.host.unitMemlock(ctx); err != nil {
		return "", err
	}
	if err := r.host.mlockall(); err != nil {
		return "", err
	}
	return previewdUnit + ": LimitMEMLOCK=infinity; mlockall permitted", nil
}

// forgeProbe is the URL the clock is read from and the file holding the
// site's CA bundle ("" for the system roots), for the forge the daemon is
// configured to serve. Any status carries a Date header; the API root is a
// URL the forge answers cheaply, without credentials.
func (r *doctorRun) forgeProbe() (rawURL, caFile string, err error) {
	switch provider := r.setting("PREVIEWD_VCS_PROVIDER"); provider {
	case "", "github":
		base, err := validate.GHESURL(r.setting("PREVIEWD_GHES_URL"))
		if err != nil {
			return "", "", fmt.Errorf("PREVIEWD_GHES_URL: %w", err)
		}
		return base + "/api/v3/", r.setting("PREVIEWD_GHES_CA_FILE"), nil
	case "gitlab":
		base, err := validate.GitLabURL(r.setting("PREVIEWD_GITLAB_URL"))
		if err != nil {
			return "", "", fmt.Errorf("PREVIEWD_GITLAB_URL: %w", err)
		}
		return base + "/api/v4/version", r.setting("PREVIEWD_GITLAB_CA_FILE"), nil
	case "forgejo":
		base, err := validate.ForgejoURL(r.setting("PREVIEWD_FORGEJO_URL"))
		if err != nil {
			return "", "", fmt.Errorf("PREVIEWD_FORGEJO_URL: %w", err)
		}
		return base + "/api/v1/version", r.setting("PREVIEWD_FORGEJO_CA_FILE"), nil
	default:
		return "", "", fmt.Errorf("PREVIEWD_VCS_PROVIDER %s: want github, gitlab or forgejo", validate.Quote(provider))
	}
}

func (r *doctorRun) checkClockSkew(ctx context.Context) (string, error) {
	rawURL, caFile, err := r.forgeProbe()
	if err != nil {
		return "", err
	}
	var ca []byte
	if caFile != "" {
		if ca, err = r.host.readFile(caFile, maxCABundleBytes); err != nil {
			return "", fmt.Errorf("CA file: %w", err)
		}
	}
	skew, err := r.host.clockSkew(ctx, rawURL, ca)
	if err != nil {
		return "", err
	}
	host := rawURL
	if u, perr := url.Parse(rawURL); perr == nil {
		host = u.Host
	}
	return fmt.Sprintf("%s: forge %+.1fs from this host (limit %s)", host, skew.Seconds(), hardening.MaxClockSkew), nil
}

func (r *doctorRun) checkTraefik(ctx context.Context) (string, error) {
	name := r.valueOr("PREVIEWD_TRAEFIK_CONTAINER", config.DefaultTraefikContainer)
	if err := r.host.proxy(ctx, name); err != nil {
		return "", err
	}
	return fmt.Sprintf("container %s is running, unprivileged, with no Docker socket and no Docker provider", name), nil
}

// oneLine flattens text that may quote an attacker (a container's name, an
// API reply): control characters become spaces, the result is one line and
// bounded.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	return textutil.Truncate(strings.Join(strings.Fields(s), " "), maxReportBytes)
}

// parseConf reads the PREVIEWD_* lines of a systemd EnvironmentFile: KEY=VALUE,
// a value optionally in single or double quotes, '#' and ';' comment lines.
// Other keys are ignored. A line that is none of these, an unterminated
// quote or a continuation line is an error: half a configuration is not read.
func parseConf(data []byte) (map[string]string, error) {
	settings := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || !confKey(key) {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", i+1)
		}
		value, err := confValue(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if strings.HasPrefix(key, "PREVIEWD_") {
			settings[key] = value
		}
	}
	return settings, nil
}

func confKey(k string) bool {
	if k == "" {
		return false
	}
	for _, c := range k {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func confValue(v string) (string, error) {
	if strings.HasSuffix(v, `\`) {
		return "", errors.New("line continuation is not supported")
	}
	if v == "" || (v[0] != '"' && v[0] != '\'') {
		return v, nil
	}
	if len(v) < 2 || v[len(v)-1] != v[0] || strings.IndexByte(v[1:len(v)-1], v[0]) >= 0 {
		return "", errors.New("unterminated or misplaced quote")
	}
	return v[1 : len(v)-1], nil
}
