package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The package scripts run as root on the operator's host, so they are
// tested here as shipped, with the hardcoded PATH and paths rewritten to a
// directory of stub commands and a temporary tree: no other change.

// scriptHarness runs scripts/<name> with its PATH set to a stub directory.
type scriptHarness struct {
	t    *testing.T
	bin  string
	root string
}

func newHarness(t *testing.T) *scriptHarness {
	t.Helper()
	return &scriptHarness{t: t, bin: t.TempDir(), root: t.TempDir()}
}

// stub installs a command that runs body.
func (h *scriptHarness) stub(name, body string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

// real links the host's command into the stub directory.
func (h *scriptHarness) real(names ...string) {
	h.t.Helper()
	for _, n := range names {
		p, err := exec.LookPath(n)
		if err != nil {
			h.t.Skipf("host has no %s", n)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, n)); err != nil {
			h.t.Fatal(err)
		}
	}
}

var (
	pathLine = regexp.MustCompile(`(?m)^PATH=.*$`)
	dirLine  = regexp.MustCompile(`(?m)^(SECRETS_DIR|RUN_DIR|CREDENTIALS_DIR)=.*$`)
)

func (h *scriptHarness) run(script string, args ...string) (code int, stderr string) {
	h.t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "scripts", script))
	if err != nil {
		h.t.Fatal(err)
	}
	text := string(src)
	if !pathLine.MatchString(text) {
		h.t.Fatalf("%s no longer sets PATH: the harness cannot confine it", script)
	}
	text = pathLine.ReplaceAllLiteralString(text, "PATH="+h.bin)
	text = dirLine.ReplaceAllStringFunc(text, func(l string) string {
		name, val, _ := strings.Cut(l, "=")
		return name + "=" + h.root + val
	})
	path := filepath.Join(h.t.TempDir(), script)
	if err := os.WriteFile(path, []byte(text), 0o755); err != nil {
		h.t.Fatal(err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		h.t.Skip("no sh")
	}
	cmd := exec.Command(sh, append([]string{path}, args...)...) // #nosec G204 -- the repository's own script, rewritten above
	cmd.Env = []string{"PATH=" + h.bin}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, errOut.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), errOut.String()
	}
	h.t.Fatal(err)
	return 0, ""
}

func TestPreinstallRefusesAHostWithoutDocker(t *testing.T) {
	for name, missing := range map[string][]string{
		"no dockerd": {"dockerd"},
		"no docker":  {"docker"},
		"neither":    {"docker", "dockerd"},
	} {
		h := newHarness(t)
		h.stub("stat", `echo cgroup2fs`)
		for _, cmd := range []string{"docker", "dockerd"} {
			skip := false
			for _, m := range missing {
				skip = skip || m == cmd
			}
			if !skip {
				h.stub(cmd, "exit 0")
			}
		}
		code, errOut := h.run("preinstall.sh", "install")
		if code == 0 || !strings.Contains(errOut, "Docker") && !strings.Contains(errOut, "docker") || !strings.Contains(errOut, "nothing was installed") {
			t.Errorf("%s: exit %d, stderr %q; want a refusal that says why", name, code, errOut)
		}
	}
}

func TestPreinstallRefusesAHostWithoutCgroupV2(t *testing.T) {
	for name, fstype := range map[string]string{
		"cgroup v1 (tmpfs root)": "tmpfs",
		"hybrid":                 "tmpfs",
		"something else":         "overlayfs",
		"empty":                  "",
	} {
		h := newHarness(t)
		h.stub("docker", "exit 0")
		h.stub("dockerd", "exit 0")
		h.stub("stat", "echo '"+fstype+"'")
		code, errOut := h.run("preinstall.sh", "install")
		if code == 0 || !strings.Contains(errOut, "cgroup v2 is required") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut)
		}
	}
	// A stat that fails is a cgroup the script could not verify.
	h := newHarness(t)
	h.stub("docker", "exit 0")
	h.stub("dockerd", "exit 0")
	h.stub("stat", "exit 1")
	if code, errOut := h.run("preinstall.sh", "install"); code == 0 || !strings.Contains(errOut, "cgroup v2 is required") {
		t.Errorf("failing stat: exit %d, stderr %q", code, errOut)
	}
}

func TestPreinstallAcceptsADockerHostOnCgroupV2(t *testing.T) {
	h := newHarness(t)
	h.stub("docker", "exit 0")
	h.stub("dockerd", "exit 0")
	h.stub("stat", `echo cgroup2fs`)
	for _, action := range []string{"install", "upgrade"} {
		if code, errOut := h.run("preinstall.sh", action); code != 0 || errOut != "" {
			t.Errorf("%s: exit %d, stderr %q", action, code, errOut)
		}
	}
}

// stagedRoot builds the runtime tree preremove cleans, with a secret in it
// and a file outside that must survive.
func stagedRoot(t *testing.T, h *scriptHarness) (secrets, outside string) {
	t.Helper()
	secrets = filepath.Join(h.root, "/run/previewd/secrets")
	if err := os.MkdirAll(filepath.Join(secrets, "pr-7-0a0a0a0a0a"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"top.env", "pr-7-0a0a0a0a0a/secrets.env"} {
		if err := os.WriteFile(filepath.Join(secrets, f), []byte("TOKEN=hunter2"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	creds := filepath.Join(h.root, "/run/credentials/previewd.service")
	if err := os.MkdirAll(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(creds, "github-app-key"), []byte("-----BEGIN PRIVATE KEY-----"), 0o400); err != nil {
		t.Fatal(err)
	}
	outside = filepath.Join(h.root, "outside.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	return secrets, outside
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestPreremoveClearsStagedSecretsOnRemoval(t *testing.T) {
	for _, action := range []string{"remove", "purge", "0"} {
		h := newHarness(t)
		h.real("find", "rmdir")
		h.stub("mountpoint", "exit 1") // not a mount: only a directory to empty
		secrets, outside := stagedRoot(t, h)

		code, errOut := h.run("preremove.sh", action)
		if code != 0 || errOut != "" {
			t.Errorf("%s: exit %d, stderr %q", action, code, errOut)
		}
		if exists(secrets) || exists(filepath.Join(h.root, "/run/previewd")) || exists(filepath.Join(h.root, "/run/credentials/previewd.service")) {
			t.Errorf("%s: staged secrets or credentials remain under %s", action, h.root)
		}
		if !exists(outside) {
			t.Errorf("%s: a file outside the secret directories was removed", action)
		}
	}
}

// An upgrade runs the old package's pre-remove too; the running daemon's
// secrets stay where they are.
func TestPreremoveLeavesAnUpgradeAlone(t *testing.T) {
	for _, action := range []string{"upgrade", "failed-upgrade", "deconfigure", "1", "2", ""} {
		h := newHarness(t)
		h.real("find", "rmdir")
		h.stub("mountpoint", "echo unmounted >&2; exit 1")
		h.stub("systemctl", "echo stopped >&2")
		secrets, _ := stagedRoot(t, h)

		code, errOut := h.run("preremove.sh", action)
		if code != 0 || errOut != "" {
			t.Errorf("%q: exit %d, stderr %q (it acted)", action, code, errOut)
		}
		if !exists(filepath.Join(secrets, "top.env")) {
			t.Errorf("%q: staged secrets were removed", action)
		}
	}
}

func TestPreremoveUnmountsTheRamfsAndStopsTheUnits(t *testing.T) {
	h := newHarness(t)
	h.real("find", "rmdir")
	log := filepath.Join(h.root, "calls.log")
	h.stub("mountpoint", "exit 0") // it is a mount point
	h.stub("umount", `echo "umount $*" >> `+log)
	h.stub("systemctl", `echo "systemctl $*" >> `+log)
	// /run/systemd/system is the real host's: only assert on umount, and on
	// systemctl when the host runs systemd.
	secrets, _ := stagedRoot(t, h)

	if code, errOut := h.run("preremove.sh", "remove"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "umount "+secrets) {
		t.Errorf("the ramfs was not unmounted: %q", calls)
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil && !strings.Contains(string(calls), "systemctl stop previewd.service previewd-proxy.service run-previewd-secrets.mount") {
		t.Errorf("the units were not stopped: %q", calls)
	}
}

// When the unmount fails (busy), the secrets are emptied in place and the
// removal is not blocked.
func TestPreremoveEmptiesWhatItCannotUnmount(t *testing.T) {
	h := newHarness(t)
	h.real("find", "rmdir")
	h.stub("mountpoint", "exit 0")
	h.stub("umount", "exit 32")
	secrets, _ := stagedRoot(t, h)

	code, errOut := h.run("preremove.sh", "remove")
	if code != 0 || !strings.Contains(errOut, "cannot unmount") {
		t.Fatalf("exit %d, stderr %q; want a warning and exit 0", code, errOut)
	}
	if entries, err := os.ReadDir(secrets); err == nil && len(entries) != 0 {
		t.Errorf("secrets left behind: %v", entries)
	}
}

// A link where the directory should be is not followed: removing the
// package must not empty whatever it points at.
func TestPreremoveDoesNotFollowASymlink(t *testing.T) {
	h := newHarness(t)
	h.real("find", "rmdir")
	h.stub("mountpoint", "exit 1")
	target := filepath.Join(h.root, "precious")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.root, "/run/previewd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(h.root, "/run/previewd/secrets")); err != nil {
		t.Fatal(err)
	}
	if code, errOut := h.run("preremove.sh", "remove"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !exists(filepath.Join(target, "data")) {
		t.Fatal("the symlink was followed and its target emptied")
	}
}

// Nothing staged, nothing mounted, no systemd: a removal on a host that
// never ran the daemon still succeeds.
func TestPreremoveOnAHostThatNeverRan(t *testing.T) {
	h := newHarness(t)
	h.real("find", "rmdir")
	if code, errOut := h.run("preremove.sh", "remove"); code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}
