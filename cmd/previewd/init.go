package main

// previewd init (V1.2 spec 3.5): the first configuration of a host, asked
// for interactively, checked by the doctor, written as the unit's
// EnvironmentFile. It never asks for or writes a secret: the file names
// credentials, which previewd setup-credentials encrypts.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kenzo-uonh/previewd/internal/config"
	"github.com/kenzo-uonh/previewd/internal/validate"
)

const initUsage = `usage:
  previewd init [-out PATH] [-force] [-user NAME]
      Ask for what a first start needs (preview domain, forge, storage paths,
      listener certificate, base images, build cgroup), run the doctor's
      checks against those settings, and write PATH (default ` + defaultConfFile + `,
      the unit's EnvironmentFile) with mode 0600. No secret is asked for or
      written: credentials are set up with previewd setup-credentials. PATH
      must not exist unless -force, which keeps the old file as
      PATH.replaced-<UTC time>. When a check fails, the file is written only
      on an explicit "yes". NAME is the doctor's service user (default ` + serviceUser + `).
`

// initAttempts is how many times one question is asked before init gives up.
const initAttempts = 3

// question is one setting init asks for.
type question struct {
	key, prompt, def string
	check            func(string) error
	// when reports whether the question applies, given the answers so far.
	when func(answers map[string]string) bool
	// optional: an empty answer leaves the key out.
	optional bool
}

func cleanAbs(what string) func(string) error {
	return func(v string) error {
		if !filepath.IsAbs(v) || v != filepath.Clean(v) || strings.ContainsAny(v, "?#") {
			return fmt.Errorf("%s: want a clean absolute path", what)
		}
		return nil
	}
}

func provider(p string) func(map[string]string) bool {
	return func(a map[string]string) bool { return a["PREVIEWD_VCS_PROVIDER"] == p }
}

func forgeURL(check func(string) (string, error)) func(string) error {
	return func(v string) error { _, err := check(v); return err }
}

// initQuestions are the settings init asks for, in order.
func initQuestions() []question {
	return []question{
		{key: "PREVIEWD_TRAEFIK_DOMAIN", prompt: "Domain the previews are served under (each one at <environment>.<domain>)", check: validate.DNSName},
		{key: "PREVIEWD_VCS_PROVIDER", prompt: "Forge: github, gitlab or forgejo (Gitea is forgejo)", def: "github", check: func(v string) error {
			switch v {
			case "github", "gitlab", "forgejo":
				return nil
			}
			return errors.New("want github, gitlab or forgejo")
		}},
		{key: "PREVIEWD_GHES_URL", prompt: "GitHub Enterprise Server URL, https://host[:port]", check: forgeURL(validate.GHESURL), when: provider("github")},
		{key: "PREVIEWD_GITHUB_APP_ID", prompt: "GitHub App ID", when: provider("github"), check: func(v string) error {
			if n, err := strconv.ParseInt(v, 10, 64); err != nil || n < 1 || strconv.FormatInt(n, 10) != v {
				return errors.New("want a positive integer")
			}
			return nil
		}},
		{key: "PREVIEWD_GHES_CA_FILE", prompt: "Site CA bundle of the forge (empty: the system roots)", optional: true, check: cleanAbs("CA bundle"), when: provider("github")},
		{key: "PREVIEWD_GITLAB_URL", prompt: "GitLab URL, https://host[:port]", check: forgeURL(validate.GitLabURL), when: provider("gitlab")},
		{key: "PREVIEWD_GITLAB_CA_FILE", prompt: "Site CA bundle of the forge (empty: the system roots)", optional: true, check: cleanAbs("CA bundle"), when: provider("gitlab")},
		{key: "PREVIEWD_FORGEJO_URL", prompt: "Forgejo or Gitea URL, https://host[:port]", check: forgeURL(validate.ForgejoURL), when: provider("forgejo")},
		{key: "PREVIEWD_FORGEJO_CA_FILE", prompt: "Site CA bundle of the forge (empty: the system roots)", optional: true, check: cleanAbs("CA bundle"), when: provider("forgejo")},
		{key: "PREVIEWD_DB_PATH", prompt: "Database file", def: "/var/lib/previewd/previewd.sqlite", check: cleanAbs("database file")},
		{key: "PREVIEWD_ROUTES_DIR", prompt: "Route documents directory (Traefik's file provider)", def: "/var/lib/previewd/routes", check: cleanAbs("routes directory")},
		{key: "PREVIEWD_TLS_CERT_FILE", prompt: "Webhook listener certificate (PEM chain)", def: "/etc/previewd/tls.crt", check: cleanAbs("certificate")},
		{key: "PREVIEWD_TLS_KEY_CREDENTIAL", prompt: "Credential name of the listener's private key", def: "tls-key", check: validate.CredentialName},
		{key: "PREVIEWD_ALLOWED_BASE_IMAGES", prompt: "Base images builds may use, name:tag@sha256:<digest>, comma-separated", check: func(v string) error {
			_, err := validate.AllowedBaseImages(v)
			return err
		}},
		{key: "PREVIEWD_BUILDKIT_CGROUP", prompt: "Build cgroup (previewd-builds.slice)", def: config.DefaultBuildCgroup, check: func(v string) error {
			if v != filepath.Clean(v) || !strings.HasPrefix(v, "/sys/fs/cgroup/") {
				return errors.New("want a clean absolute path under /sys/fs/cgroup")
			}
			return nil
		}},
	}
}

// credentialsOf names the systemd credentials the daemon reads with these
// settings, for the next steps.
func credentialsOf(a map[string]string) []string {
	names := map[string][]string{
		"github":  {"webhook_secret", "github-app-key"},
		"gitlab":  {"gitlab-api-token", "gitlab-webhook-secret"},
		"forgejo": {"forgejo-api-token", "forgejo-webhook-secret"},
	}[a["PREVIEWD_VCS_PROVIDER"]]
	return append(names, a["PREVIEWD_TLS_KEY_CREDENTIAL"])
}

// renderConf writes the answers as an EnvironmentFile, in question order.
// Every value passed its validator, none holds a space, a quote or a line
// break: none needs quoting.
func renderConf(qs []question, a map[string]string, now time.Time) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# previewd configuration, written by previewd init on %s.\n", now.UTC().Format("2006-01-02 15:04 UTC"))
	b.WriteString("# The unit's EnvironmentFile (docs/configuration.md). No secret belongs here:\n")
	b.WriteString("# secrets are systemd credentials (previewd setup-credentials).\n")
	for _, q := range qs {
		v, ok := a[q.key]
		if !ok {
			continue
		}
		if strings.ContainsAny(v, " \t\r\n\"'\\$`;") {
			return nil, fmt.Errorf("%s: the value holds a character an EnvironmentFile would interpret", q.key)
		}
		fmt.Fprintf(&b, "%s=%s\n", q.key, v)
	}
	return []byte(b.String()), nil
}

// runInit is `previewd init`. now stamps the file and a replaced one.
func runInit(ctx context.Context, args []string, stdin io.Reader, getenv func(string) string, stdout, stderr io.Writer, host doctorHost, now func() time.Time) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := initCommand(ctx, args, bufio.NewReader(stdin), getenv, out, diag, host, now)
	if code == exitOK && out.err != nil {
		diag.printf("previewd init: write: %v\n", out.err)
		return exitUsage
	}
	return code
}

func initCommand(ctx context.Context, args []string, in *bufio.Reader, getenv func(string) string, out, diag *console, host doctorHost, now func() time.Time) int {
	flags := flag.NewFlagSet("previewd init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("out", defaultConfFile, "")
	force := flags.Bool("force", false, "")
	account := flags.String("user", serviceUser, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || cleanAbs("-out")(*path) != nil || *account == "" {
		diag.printf("previewd init: invalid arguments\n%s", initUsage)
		return exitUsage
	}
	if _, err := os.Lstat(*path); err == nil && !*force {
		diag.printf("previewd init: %s exists: pass -force to replace it (the old file is kept beside it)\n", *path)
		return exitUsage
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		diag.printf("previewd init: %v\n", err)
		return exitUsage
	}

	qs := initQuestions()
	answers := map[string]string{}
	out.printf("previewd init: %s\n", *path)
	for _, q := range qs {
		if q.when != nil && !q.when(answers) {
			continue
		}
		v, err := ask(in, out, q)
		if err != nil {
			diag.printf("previewd init: %s: %v\n", q.key, err)
			return exitUsage
		}
		if v != "" {
			answers[q.key] = v
		}
	}
	conf, err := renderConf(qs, answers, now())
	if err != nil {
		diag.printf("previewd init: %v\n", err)
		return exitUsage
	}

	// The doctor reads the settings as they will be written.
	checked := host
	checked.readFile = func(p string, limit int64) ([]byte, error) {
		if p == *path {
			return conf, nil
		}
		return host.readFile(p, limit)
	}
	out.printf("\n")
	doctorCode := doctorCommand(ctx, []string{"-conf", *path, "-user", *account}, getenv, checked, out, diag)
	if doctorCode == exitUsage {
		return exitUsage
	}
	if doctorCode != exitOK {
		out.printf("\nSome checks failed: previewd will refuse to start until they pass. Write %s anyway? [y/N] ", *path)
		line, _ := in.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			diag.printf("previewd init: nothing written\n")
			return exitChecksFailed
		}
	}
	replaced, err := writeConf(*path, conf, now())
	if err != nil {
		diag.printf("previewd init: %v\n", err)
		return exitUsage
	}
	if replaced != "" {
		out.printf("previous configuration kept as %s\n", replaced)
	}
	out.printf("wrote %s (mode 0600)\n\nNext:\n", *path)
	for _, name := range credentialsOf(answers) {
		out.printf("  previewd setup-credentials %s\n", name)
	}
	out.printf("  then add the LoadCredentialEncrypted= lines it prints with systemctl edit previewd,\n  and run previewd doctor before systemctl start previewd.\n")
	return doctorCode
}

// ask asks q until it gets a valid answer, initAttempts times at most.
func ask(in *bufio.Reader, out *console, q question) (string, error) {
	for range initAttempts {
		if q.def != "" {
			out.printf("%s [%s]: ", q.prompt, q.def)
		} else {
			out.printf("%s: ", q.prompt)
		}
		line, err := in.ReadString('\n')
		if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
			return "", errors.New("no answer (end of input)")
		}
		v := strings.TrimSpace(line)
		switch {
		case v == "" && q.def != "":
			v = q.def
		case v == "" && q.optional:
			return "", nil
		}
		if v == "" {
			out.printf("  an answer is required\n")
			continue
		}
		if err := q.check(v); err != nil {
			out.printf("  %s\n", oneLine(err.Error()))
			continue
		}
		return v, nil
	}
	return "", fmt.Errorf("no valid answer after %d attempts", initAttempts)
}

// writeConf writes conf to path with mode 0600, atomically: a temporary
// file in the same directory, synced, then renamed over path. An existing
// file is first renamed to path.replaced-<UTC time>, whose name it returns;
// nothing is ever deleted.
func writeConf(path string, conf []byte, now time.Time) (replaced string, err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".previewd.conf.*")
	if err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(tmp.Name()))
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", errors.Join(fmt.Errorf("write %s: %w", path, err), tmp.Close())
	}
	if _, err := tmp.Write(conf); err != nil {
		return "", errors.Join(fmt.Errorf("write %s: %w", path, err), tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return "", errors.Join(fmt.Errorf("write %s: %w", path, err), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		replaced = path + ".replaced-" + now.UTC().Format("20060102T150405Z")
		if err := os.Rename(path, replaced); err != nil {
			return "", fmt.Errorf("keep %s: %w", path, err)
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return replaced, fmt.Errorf("write %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return replaced, fmt.Errorf("write %s: %w", path, err)
	}
	return replaced, nil
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) (err error) {
	d, err := os.Open(dir) // #nosec G304 -- the directory of the operator's -out path
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	return d.Sync()
}
