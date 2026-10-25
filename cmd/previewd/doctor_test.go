package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// probeLog records what the doctor asked of the host.
type probeLog struct {
	cgroupDir, stagingDir, proxy, skewURL, user string
	uid                                         int
	caPEM                                       []byte
	skewCalls                                   int
	stagingCalls                                int
}

// healthyHost is a host on which every probe passes; mutate the returned
// struct's funcs to fail one.
func healthyHost(log *probeLog, files map[string]string) doctorHost {
	return doctorHost{
		readFile: func(path string, _ int64) ([]byte, error) {
			if c, ok := files[path]; ok {
				return []byte(c), nil
			}
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		},
		buildCgroup:  func(dir string) error { log.cgroupDir = dir; return nil },
		dockerEgress: func(context.Context) error { return nil },
		stagingMount: func(dir string, uid int) error {
			log.stagingDir, log.uid = dir, uid
			log.stagingCalls++
			return nil
		},
		lookupUID:   func(user string) (int, error) { log.user = user; return 998, nil },
		unitMemlock: func(context.Context) error { return nil },
		mlockall:    func() error { return nil },
		clockSkew: func(_ context.Context, url string, ca []byte) (time.Duration, error) {
			log.skewURL, log.caPEM = url, ca
			log.skewCalls++
			return 400 * time.Millisecond, nil
		},
		proxy: func(_ context.Context, name string) error { log.proxy = name; return nil },
	}
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const ghesEnv = "https://ghes.example.test"

func doctor(t *testing.T, host doctorHost, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runDoctor(context.Background(), args, envOf(env), &out, &errOut, host)
	return code, out.String(), errOut.String()
}

func TestDoctorAllChecksPass(t *testing.T) {
	var log probeLog
	code, out, errOut := doctor(t, healthyHost(&log, nil), map[string]string{"PREVIEWD_GHES_URL": ghesEnv})
	if code != exitOK || errOut != "" {
		t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, errOut, out)
	}
	if n := strings.Count(out, "[PASS]"); n != 6 || strings.Contains(out, "[FAIL]") {
		t.Fatalf("want six passes and no failure:\n%s", out)
	}
	for _, want := range []string{"build cgroup", "dockerd egress", "secrets staging", "memory lock", "clock skew", "traefik isolation", "6 of 6"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// A failure does not stop the run: the operator sees every problem at once,
// and the exit code is 1.
func TestDoctorRunsEveryCheckAndExitsOneOnAFailure(t *testing.T) {
	checks := map[string]func(*doctorHost){
		"build cgroup": func(h *doctorHost) {
			h.buildCgroup = func(string) error { return errors.New("memory.swap.max is \"max\"") }
		},
		"dockerd egress": func(h *doctorHost) {
			h.dockerEgress = func(context.Context) error { return errors.New("IPAddressDeny unset") }
		},
		"secrets staging": func(h *doctorHost) { h.stagingMount = func(string, int) error { return errors.New("is tmpfs") } },
		"memory lock": func(h *doctorHost) {
			h.unitMemlock = func(context.Context) error { return errors.New("LimitMEMLOCK=8388608") }
		},
		"memory lock probe": func(h *doctorHost) {
			h.mlockall = func() error { return errors.New("mlockall: operation not permitted") }
		},
		"clock skew": func(h *doctorHost) {
			h.clockSkew = func(context.Context, string, []byte) (time.Duration, error) {
				return 9 * time.Second, errors.New("the forge is 9s from this host")
			}
		},
		"traefik isolation": func(h *doctorHost) {
			h.proxy = func(context.Context, string) error { return errors.New("mounts socket /var/run/docker.sock") }
		},
	}
	for name, breakIt := range checks {
		var log probeLog
		host := healthyHost(&log, nil)
		breakIt(&host)
		code, out, _ := doctor(t, host, map[string]string{"PREVIEWD_GHES_URL": ghesEnv})
		if code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		if strings.Count(out, "[FAIL]") != 1 || strings.Count(out, "[PASS]") != 5 {
			t.Errorf("%s: want one failure and five passes:\n%s", name, out)
		}
		if !strings.Contains(out, "5 of 6") {
			t.Errorf("%s: no summary:\n%s", name, out)
		}
	}
}

func TestDoctorAllChecksFailing(t *testing.T) {
	boom := errors.New("boom")
	host := doctorHost{
		readFile:     func(string, int64) ([]byte, error) { return nil, fs.ErrNotExist },
		buildCgroup:  func(string) error { return boom },
		dockerEgress: func(context.Context) error { return boom },
		stagingMount: func(string, int) error { return boom },
		lookupUID:    func(string) (int, error) { return 0, boom },
		unitMemlock:  func(context.Context) error { return boom },
		mlockall:     func() error { return boom },
		clockSkew:    func(context.Context, string, []byte) (time.Duration, error) { return 0, boom },
		proxy:        func(context.Context, string) error { return boom },
	}
	code, out, _ := doctor(t, host, nil)
	if code != 1 || strings.Count(out, "[FAIL]") != 6 || strings.Contains(out, "[PASS]") || !strings.Contains(out, "0 of 6") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestDoctorDefaultsAndSettings(t *testing.T) {
	var log probeLog
	code, out, _ := doctor(t, healthyHost(&log, nil), map[string]string{"PREVIEWD_GHES_URL": ghesEnv})
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if log.cgroupDir != "/sys/fs/cgroup/previewd.slice/previewd-builds.slice" ||
		log.stagingDir != "/run/previewd/secrets" || log.user != "previewd" || log.uid != 998 ||
		log.proxy != "traefik-proxy" || log.skewURL != ghesEnv+"/api/v3/" {
		t.Fatalf("defaults not passed to the probes: %+v", log)
	}

	log = probeLog{}
	code, out, _ = doctor(t, healthyHost(&log, nil), map[string]string{
		"PREVIEWD_VCS_PROVIDER":        "gitlab",
		"PREVIEWD_GITLAB_URL":          "https://gitlab.example.test",
		"PREVIEWD_SECRETS_STAGING_DIR": "/run/site/secrets",
		"PREVIEWD_BUILDKIT_CGROUP":     "/sys/fs/cgroup/site.slice/builds.slice",
		"PREVIEWD_TRAEFIK_CONTAINER":   "edge-proxy",
		"PREVIEWD_GHES_URL":            "", // not this forge's key
	}, "-user", "svc-previewd")
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if log.cgroupDir != "/sys/fs/cgroup/site.slice/builds.slice" || log.stagingDir != "/run/site/secrets" ||
		log.user != "svc-previewd" || log.proxy != "edge-proxy" || log.skewURL != "https://gitlab.example.test/api/v4/version" {
		t.Fatalf("settings not passed to the probes: %+v", log)
	}
}

// The site CA bundle is read from the forge's CA key and handed to the skew
// probe: the GHES of a bank is signed by the bank's CA.
func TestDoctorPassesTheForgeCA(t *testing.T) {
	for provider, tc := range map[string]struct{ urlKey, caKey, url string }{
		"github":  {"PREVIEWD_GHES_URL", "PREVIEWD_GHES_CA_FILE", ghesEnv},
		"gitlab":  {"PREVIEWD_GITLAB_URL", "PREVIEWD_GITLAB_CA_FILE", "https://gitlab.example.test"},
		"forgejo": {"PREVIEWD_FORGEJO_URL", "PREVIEWD_FORGEJO_CA_FILE", "https://forge.example.test"},
	} {
		var log probeLog
		host := healthyHost(&log, map[string]string{"/etc/site/ca.pem": "PEM BYTES"})
		code, out, _ := doctor(t, host, map[string]string{"PREVIEWD_VCS_PROVIDER": provider, tc.urlKey: tc.url, tc.caKey: "/etc/site/ca.pem"})
		if code != exitOK || string(log.caPEM) != "PEM BYTES" {
			t.Errorf("%s: exit %d, CA %q:\n%s", provider, code, log.caPEM, out)
		}
	}
	// An unreadable CA file fails the check; the probe is not run without it.
	var log probeLog
	code, out, _ := doctor(t, healthyHost(&log, nil), map[string]string{"PREVIEWD_GHES_URL": ghesEnv, "PREVIEWD_GHES_CA_FILE": "/etc/site/missing.pem"})
	if code != 1 || log.skewCalls != 0 || !strings.Contains(out, "[FAIL] clock skew") {
		t.Fatalf("exit %d, skew calls %d:\n%s", code, log.skewCalls, out)
	}
}

// What cannot be configured cannot be checked: each failure is the check's
// own, and the probe behind it never runs.
func TestDoctorFailsClosedOnBadSettings(t *testing.T) {
	for name, tc := range map[string]struct {
		env     map[string]string
		failing string
	}{
		"no forge URL":            {nil, "clock skew"},
		"plain http forge":        {map[string]string{"PREVIEWD_GHES_URL": "http://ghes.example.test"}, "clock skew"},
		"forge URL with a path":   {map[string]string{"PREVIEWD_GHES_URL": ghesEnv + "/x"}, "clock skew"},
		"unknown provider":        {map[string]string{"PREVIEWD_VCS_PROVIDER": "gitea", "PREVIEWD_GHES_URL": ghesEnv}, "clock skew"},
		"cgroup outside cgroupfs": {map[string]string{"PREVIEWD_GHES_URL": ghesEnv, "PREVIEWD_BUILDKIT_CGROUP": "/tmp/x"}, "build cgroup"},
		"relative staging dir":    {map[string]string{"PREVIEWD_GHES_URL": ghesEnv, "PREVIEWD_SECRETS_STAGING_DIR": "secrets"}, "secrets staging"},
		"unclean staging dir":     {map[string]string{"PREVIEWD_GHES_URL": ghesEnv, "PREVIEWD_SECRETS_STAGING_DIR": "/run/previewd/../x"}, "secrets staging"},
	} {
		var log probeLog
		code, out, _ := doctor(t, healthyHost(&log, nil), tc.env)
		if code != 1 || strings.Count(out, "[FAIL]") != 1 || !strings.Contains(out, "[FAIL] "+tc.failing) {
			t.Errorf("%s: exit %d:\n%s", name, code, out)
		}
		if tc.failing == "clock skew" && log.skewCalls != 0 || tc.failing == "secrets staging" && log.stagingCalls != 0 {
			t.Errorf("%s: the probe ran on a bad setting: %+v", name, log)
		}
	}
}

func TestDoctorFailsWhenTheServiceUserDoesNotExist(t *testing.T) {
	var log probeLog
	host := healthyHost(&log, nil)
	host.lookupUID = func(string) (int, error) { return 0, errors.New("unknown user previewd") }
	code, out, _ := doctor(t, host, map[string]string{"PREVIEWD_GHES_URL": ghesEnv})
	if code != 1 || log.stagingCalls != 0 || !strings.Contains(out, "[FAIL] secrets staging") || !strings.Contains(out, "unknown user previewd") {
		t.Fatalf("exit %d, staging calls %d:\n%s", code, log.stagingCalls, out)
	}
}

func TestDoctorReadsTheConfFileFirst(t *testing.T) {
	var log probeLog
	conf := "# site settings\n" +
		"PREVIEWD_GHES_URL=\"https://ghes.conf.test\"\n" +
		"PREVIEWD_TRAEFIK_CONTAINER='conf-proxy'\n" +
		"; another comment\n\n" +
		"SOMETHING_ELSE=ignored\n"
	host := healthyHost(&log, map[string]string{defaultConfFile: conf})
	// The environment names other values: the file wins, as it does for the unit.
	code, out, _ := doctor(t, host, map[string]string{"PREVIEWD_GHES_URL": ghesEnv, "PREVIEWD_TRAEFIK_CONTAINER": "env-proxy", "PREVIEWD_SECRETS_STAGING_DIR": "/run/env/secrets"})
	if code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if log.skewURL != "https://ghes.conf.test/api/v3/" || log.proxy != "conf-proxy" || log.stagingDir != "/run/env/secrets" {
		t.Fatalf("file > environment > default not respected: %+v", log)
	}

	// -conf names another file; it must exist.
	log = probeLog{}
	host = healthyHost(&log, map[string]string{"/srv/site.conf": "PREVIEWD_GHES_URL=https://ghes.site.test\n"})
	if code, out, _ := doctor(t, host, nil, "-conf", "/srv/site.conf"); code != exitOK || log.skewURL != "https://ghes.site.test/api/v3/" {
		t.Fatalf("-conf: exit %d, %+v:\n%s", code, log, out)
	}
	if code, _, _ := doctor(t, healthyHost(&probeLog{}, nil), nil, "-conf", "/srv/absent.conf"); code != exitUsage {
		t.Fatalf("-conf naming a missing file: exit %d, want %d", code, exitUsage)
	}
}

func TestDoctorUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args  []string
		files map[string]string
	}{
		"unknown flag":     {[]string{"-fix"}, nil},
		"extra argument":   {[]string{"now"}, nil},
		"empty -user":      {[]string{"-user", ""}, nil},
		"empty -conf":      {[]string{"-conf", ""}, nil},
		"malformed conf":   {nil, map[string]string{defaultConfFile: "PREVIEWD_GHES_URL\n"}},
		"conf, bad key":    {nil, map[string]string{defaultConfFile: "PREVIEWD GHES=1\n"}},
		"conf, open quote": {nil, map[string]string{defaultConfFile: "PREVIEWD_GHES_URL=\"https://x\n"}},
	} {
		var log probeLog
		code, out, errOut := doctor(t, healthyHost(&log, tc.files), map[string]string{"PREVIEWD_GHES_URL": ghesEnv}, tc.args...)
		if code != exitUsage || out != "" || errOut == "" || log.skewCalls != 0 {
			t.Errorf("%s: exit %d, stdout %q, stderr %q, probes run %d", name, code, out, errOut, log.skewCalls)
		}
	}
}

// An error from the host can quote what an attacker controls (a container
// name, an API reply): one line, bounded, no control characters.
func TestDoctorReportsErrorsOnOneBoundedLine(t *testing.T) {
	var log probeLog
	host := healthyHost(&log, nil)
	host.proxy = func(context.Context, string) error {
		return errors.New("inspect: \x1b[31mred\x1b[0m\nsecond line\r\n" + strings.Repeat("x", 5000))
	}
	_, out, _ := doctor(t, host, map[string]string{"PREVIEWD_GHES_URL": ghesEnv})
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[FAIL]") {
			if len(line) > 600 || strings.ContainsAny(line, "\x1b\r") {
				t.Fatalf("unbounded or unsafe line (%d bytes): %q", len(line), line)
			}
			if !strings.Contains(line, "second line") {
				t.Fatalf("the newline cut the message instead of being flattened: %q", line)
			}
			return
		}
	}
	t.Fatalf("no failure line:\n%s", out)
}

func TestDoctorOutputFailureIsNotSuccess(t *testing.T) {
	var log probeLog
	var errOut bytes.Buffer
	code := runDoctor(context.Background(), nil, envOf(map[string]string{"PREVIEWD_GHES_URL": ghesEnv}), brokenPipe{}, &errOut, healthyHost(&log, nil))
	if code != exitUsage {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}

func TestParseConf(t *testing.T) {
	got, err := parseConf([]byte("PREVIEWD_A=1\r\nPREVIEWD_B = two words \nPREVIEWD_C=\"q # not a comment\"\nPREVIEWD_D=\nPREVIEWD_A=3\nOTHER=x\n#PREVIEWD_E=4\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"PREVIEWD_A": "3", "PREVIEWD_B": "two words", "PREVIEWD_C": "q # not a comment", "PREVIEWD_D": ""}
	if len(got) != len(want) {
		t.Fatalf("parseConf = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, bad := range []string{"PREVIEWD_A\n", "=1\n", "PREVIEWD_A=\"unterminated\n", "PREVIEWD_A='x\n", "PREVIEWD_A=x\\\ncontinued\n", "PREVIEWD A=1\n", "PREVIEWD_A=\"x\"y\n"} {
		if _, err := parseConf([]byte(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A probe left nil would panic on a real host: every field of the production
// host is set.
func TestProductionDoctorHostIsComplete(t *testing.T) {
	h := newDoctorHost()
	if h.readFile == nil || h.buildCgroup == nil || h.dockerEgress == nil || h.stagingMount == nil || h.lookupUID == nil ||
		h.unitMemlock == nil || h.mlockall == nil || h.clockSkew == nil || h.proxy == nil {
		t.Fatalf("incomplete production host: %+v", h)
	}
}
