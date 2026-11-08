package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var initNow = time.Date(2026, 10, 25, 9, 30, 0, 0, time.UTC)

const initBase = "alpine:3.20@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"

func runInitCmd(t *testing.T, host doctorHost, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runInit(context.Background(), args, strings.NewReader(stdin), func(string) string { return "" }, &out, &errOut, host,
		func() time.Time { return initNow })
	return code, out.String(), errOut.String()
}

// answers joins the lines typed at the prompts.
func answers(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func TestInitWritesTheConfigurationTheDoctorChecked(t *testing.T) {
	var log probeLog
	path := filepath.Join(t.TempDir(), "previewd.conf")
	code, out, errOut := runInitCmd(t, healthyHost(&log, nil), answers(
		"preview.corp.example", // domain
		"forgejo",              // forge
		"https://forge.corp.example:3000",
		"",                     // CA: system roots
		"",                     // database: default
		"/srv/previewd/routes", // routes
		"",                     // certificate: default
		"",                     // key credential: default
		initBase,               // base images
		"",                     // build cgroup: default
	), "-out", path)
	if code != exitOK || errOut != "" {
		t.Fatalf("init = %d, %q:\n%s", code, errOut, out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PREVIEWD_TRAEFIK_DOMAIN=preview.corp.example\n", "PREVIEWD_VCS_PROVIDER=forgejo\n",
		"PREVIEWD_FORGEJO_URL=https://forge.corp.example:3000\n", "PREVIEWD_DB_PATH=/var/lib/previewd/previewd.sqlite\n",
		"PREVIEWD_ROUTES_DIR=/srv/previewd/routes\n", "PREVIEWD_TLS_CERT_FILE=/etc/previewd/tls.crt\n",
		"PREVIEWD_TLS_KEY_CREDENTIAL=tls-key\n", "PREVIEWD_ALLOWED_BASE_IMAGES=" + initBase + "\n",
		"PREVIEWD_BUILDKIT_CGROUP=/sys/fs/cgroup/previewd.slice/previewd-builds.slice\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("conf lacks %q:\n%s", want, got)
		}
	}
	// Only the chosen forge's keys; an empty optional answer leaves its key out.
	for _, absent := range []string{"PREVIEWD_GHES", "PREVIEWD_GITLAB", "PREVIEWD_GITHUB", "PREVIEWD_FORGEJO_CA_FILE"} {
		if strings.Contains(string(got), absent) {
			t.Errorf("conf holds %s:\n%s", absent, got)
		}
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v; want 0600", fi.Mode(), err)
	}
	// The doctor read the settings as written: the forge's clock, by its URL.
	if log.skewURL != "https://forge.corp.example:3000/api/v1/version" || !strings.Contains(out, "6 of 6 checks passed") {
		t.Errorf("doctor: skew URL %q:\n%s", log.skewURL, out)
	}
	for _, want := range []string{"setup-credentials forgejo-api-token", "setup-credentials forgejo-webhook-secret", "setup-credentials tls-key"} {
		if !strings.Contains(out, want) {
			t.Errorf("next steps lack %q:\n%s", want, out)
		}
	}
	// The file is one the daemon's parser reads back.
	if settings, err := parseConf(got); err != nil || settings["PREVIEWD_VCS_PROVIDER"] != "forgejo" {
		t.Errorf("parseConf = %v, %v", settings, err)
	}
}

func TestInitAsksAgainAndAsksOnlyTheForgesQuestions(t *testing.T) {
	var log probeLog
	path := filepath.Join(t.TempDir(), "previewd.conf")
	code, out, _ := runInitCmd(t, healthyHost(&log, map[string]string{"/etc/previewd/ghes-ca.pem": "PEM"}), answers(
		"Not A Domain!", "preview.corp.example",
		"bitbucket", "github",
		"http://ghes.corp", "https://ghes.corp",
		"0", "31337",
		"relative/ca.pem", "/etc/previewd/ghes-ca.pem",
		"", "", "", "", "alpine:3.20", initBase, "",
	), "-out", path)
	got, _ := os.ReadFile(path)
	if code != exitOK || !strings.Contains(string(got), "PREVIEWD_GITHUB_APP_ID=31337\n") || !strings.Contains(string(got), "PREVIEWD_GHES_CA_FILE=/etc/previewd/ghes-ca.pem\n") {
		t.Fatalf("init = %d:\n%s\nconf:\n%s", code, out, got)
	}
	if n := strings.Count(out, "Forgejo or Gitea URL"); n != 0 {
		t.Errorf("asked another forge's question:\n%s", out)
	}
}

// Fails closed: a failed check writes nothing unless the operator says yes;
// an existing file is never replaced without -force, and is kept beside the
// new one when it is.
func TestInitWritesNothingOnAFailedCheckUnlessTold(t *testing.T) {
	typed := answers("preview.corp.example", "gitlab", "https://gitlab.corp", "", "", "", "", "", initBase, "")
	for _, reply := range []string{"", "n", "no", "maybe"} {
		var log probeLog
		host := healthyHost(&log, nil)
		host.mlockall = func() error { return errors.New("RLIMIT_MEMLOCK too low") }
		path := filepath.Join(t.TempDir(), "previewd.conf")
		code, out, _ := runInitCmd(t, host, typed+reply+"\n", "-out", path)
		if _, err := os.Stat(path); code != exitChecksFailed || err == nil {
			t.Errorf("reply %q: exit %d, file written (%v):\n%s", reply, code, err == nil, out)
		}
	}
	var log probeLog
	host := healthyHost(&log, nil)
	host.mlockall = func() error { return errors.New("RLIMIT_MEMLOCK too low") }
	path := filepath.Join(t.TempDir(), "previewd.conf")
	if code, out, _ := runInitCmd(t, host, typed+"yes\n", "-out", path); code != exitChecksFailed {
		t.Errorf("yes: exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("yes: nothing written: %v", err)
	}

	// Exists: refused before any question; -force keeps the old file.
	if code, _, errOut := runInitCmd(t, healthyHost(&log, nil), typed, "-out", path); code != exitUsage || !strings.Contains(errOut, "-force") {
		t.Errorf("existing file: exit %d, %q", code, errOut)
	}
	old, _ := os.ReadFile(path)
	code, out, _ := runInitCmd(t, healthyHost(&log, nil), typed, "-out", path, "-force")
	kept := path + ".replaced-20261025T093000Z"
	if b, err := os.ReadFile(kept); code != exitOK || err != nil || !bytes.Equal(b, old) {
		t.Errorf("-force: exit %d, kept %v:\n%s", code, err, out)
	}
}

func TestInitRefusesBadArgumentsAndEndOfInput(t *testing.T) {
	var log probeLog
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		args  []string
		stdin string
	}{
		"relative out":     {[]string{"-out", "previewd.conf"}, ""},
		"an argument":      {[]string{"-out", filepath.Join(dir, "a"), "x"}, ""},
		"end of input":     {[]string{"-out", filepath.Join(dir, "b")}, "preview.corp.example\n"},
		"three bad tries":  {[]string{"-out", filepath.Join(dir, "c")}, answers("x y", "x y", "x y")},
		"no out directory": {[]string{"-out", filepath.Join(dir, "missing", "previewd.conf")}, answers("preview.corp.example", "gitlab", "https://gitlab.corp", "", "", "", "", "", initBase, "")},
	} {
		if code, _, _ := runInitCmd(t, healthyHost(&log, nil), tc.stdin, tc.args...); code != exitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
}

func TestRenderConfRefusesWhatAnEnvironmentFileInterprets(t *testing.T) {
	qs := []question{{key: "PREVIEWD_X"}}
	for _, v := range []string{"a b", "a\nPREVIEWD_Y=1", `a"b`, "a'b", `a\b`, "$HOME", "a;b", "`id`"} {
		if _, err := renderConf(qs, map[string]string{"PREVIEWD_X": v}, initNow); err == nil {
			t.Errorf("%q rendered", v)
		}
	}
}
