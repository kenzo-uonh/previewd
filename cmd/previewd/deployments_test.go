package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Day-2 deployment files are code: previewd-proxy.service is the same
// container as docker-compose.yml, and the mount unit is what `previewd
// doctor` checks. These tests keep them from drifting apart or loosening.

func deploymentFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deployments", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// directives returns the non-comment lines of a unit, with the backslash
// continuations joined.
func directives(unit string) []string {
	var out []string
	var cur string
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if cur == "" && (line == "" || strings.HasPrefix(line, "#")) {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cur += strings.TrimSuffix(line, `\`) + " "
			continue
		}
		out = append(out, strings.Join(strings.Fields(cur+line), " "))
		cur = ""
	}
	return out
}

func directive(t *testing.T, unit, prefix string) string {
	t.Helper()
	for _, d := range directives(unit) {
		if strings.HasPrefix(d, prefix) {
			return d
		}
	}
	t.Fatalf("no directive starting with %q", prefix)
	return ""
}

func TestProxyUnitMatchesTheComposeProxy(t *testing.T) {
	unit, compose, traefik := deploymentFile(t, "previewd-proxy.service"), deploymentFile(t, "docker-compose.yml"), deploymentFile(t, "traefik.yml")

	image := regexp.MustCompile(`traefik:v[0-9.]+@sha256:[0-9a-f]{64}`)
	if u, c := image.FindString(unit), image.FindString(compose); u == "" || u != c {
		t.Errorf("image: unit %q, compose %q; they must be the same digest-pinned reference", u, c)
	}
	for _, shared := range []string{"172.30.255.2", "172.30.255.0/24", "previewd-proxy"} {
		for name, file := range map[string]string{"unit": unit, "compose": compose} {
			if !strings.Contains(file, shared) {
				t.Errorf("%s lacks %q", name, shared)
			}
		}
	}
	if !strings.Contains(traefik, `"172.30.255.2:80"`) {
		t.Error("traefik.yml no longer binds the address the unit gives the container")
	}
	// The metrics entry point (ingress activity sensing) binds the proxy's
	// address too, carries router labels, and is published nowhere.
	for _, want := range []string{`address: "172.30.255.2:8082"`, "entryPoint: metrics", "addRoutersLabels: true"} {
		if !strings.Contains(traefik, want) {
			t.Errorf("traefik.yml lacks %s", want)
		}
	}
	for name, file := range map[string]string{"previewd-proxy.service": unit, "docker-compose.yml": compose} {
		if strings.Contains(file, "8082") {
			t.Errorf("%s publishes the metrics entry point", name)
		}
	}
}

func TestProxyUnitIsolation(t *testing.T) {
	unit := deploymentFile(t, "previewd-proxy.service")
	run := directive(t, unit, "ExecStart=/usr/bin/docker run")

	for _, want := range []string{
		"--pull=never", "--read-only", "--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE", "--security-opt=no-new-privileges:true",
		"--network=previewd-proxy", "--cgroup-parent=system.slice", "--dns=127.0.0.1",
		"/etc/previewd/traefik.yml:/etc/traefik/traefik.yml:ro", "${PREVIEWD_ROUTES_DIR}:/etc/traefik/routes:ro",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("docker run lacks %q: %s", want, run)
		}
	}
	// No socket, no privilege, no label-driven routing, no writable mount, no
	// host namespace: the properties the daemon verifies at every start.
	for _, forbidden := range []string{".sock", "--privileged", "--cap-add=ALL", "--cap-add=SYS", "providers.docker", "--label", "traefik.enable",
		"--network=host", "--pid=host", "--userns=host", "--volume=/:", "--volumes-from"} {
		if strings.Contains(strings.ToLower(run), forbidden) {
			t.Errorf("docker run contains %q: %s", forbidden, run)
		}
	}
	for _, d := range directives(unit) {
		if strings.Contains(d, "docker.sock") || strings.Contains(d, "docker compose") || strings.Contains(d, "docker-compose") {
			t.Errorf("directive depends on the socket or compose: %s", d)
		}
	}
	// A running container is not this unit's to remove.
	if d := directive(t, unit, "ExecStartPre=-/usr/bin/docker rm"); strings.Contains(d, "--force") || strings.Contains(d, " -f") {
		t.Errorf("stale-container cleanup forces removal: %s", d)
	}
	// Not root, and no more privilege than the docker CLI needs.
	for _, want := range []string{"User=previewd", "NoNewPrivileges=yes", "IPAddressDeny=any", "CapabilityBoundingSet=", "RestrictAddressFamilies=AF_UNIX"} {
		found := false
		for _, d := range directives(unit) {
			found = found || d == want
		}
		if !found {
			t.Errorf("unit lacks %s", want)
		}
	}
}

func TestSecretsMountUnitIsRamfs(t *testing.T) {
	unit := deploymentFile(t, "run-previewd-secrets.mount")
	got := map[string]string{}
	for _, d := range directives(unit) {
		if k, v, ok := strings.Cut(d, "="); ok {
			got[k] = v
		}
	}
	if got["What"] != "ramfs" || got["Type"] != "ramfs" || got["Where"] != "/run/previewd/secrets" {
		t.Errorf("mount unit is not a ramfs at /run/previewd/secrets: %v", got)
	}
	for _, opt := range []string{"mode=0700", "nosuid", "nodev", "noexec"} {
		if !strings.Contains(got["Options"], opt) {
			t.Errorf("Options=%q lacks %s", got["Options"], opt)
		}
	}
	if strings.Contains(unit, "tmpfs") && strings.Contains(strings.Join(directives(unit), "\n"), "tmpfs") {
		t.Error("the mount unit names tmpfs, whose pages can be swapped")
	}
	// The unit file name is the escaped Where= (systemd-escape --path).
	if want := strings.TrimPrefix(strings.ReplaceAll(got["Where"], "/", "-"), "-") + ".mount"; want != "run-previewd-secrets.mount" {
		t.Errorf("Where=%s is escaped as %s, not the file name run-previewd-secrets.mount", got["Where"], want)
	}
}

func TestDaemonUnitIsOrderedAfterWhatItVerifies(t *testing.T) {
	unit := deploymentFile(t, "previewd.service")
	for _, want := range []string{"RequiresMountsFor=/run/previewd/secrets", "LimitMEMLOCK=infinity", "LimitCORE=0"} {
		found := false
		for _, d := range directives(unit) {
			found = found || d == want
		}
		if !found {
			t.Errorf("previewd.service lacks %s", want)
		}
	}
	if after := directive(t, unit, "After="); !strings.Contains(after, "previewd-proxy.service") || !strings.Contains(after, "docker.service") {
		t.Errorf("%s", after)
	}
	// The proxy is the site's choice (compose may run it): ordering, never a pull-in.
	for _, d := range directives(unit) {
		if strings.HasPrefix(d, "Wants=") && strings.Contains(d, "previewd-proxy") || strings.HasPrefix(d, "Requires=") && strings.Contains(d, "previewd-proxy") {
			t.Errorf("previewd.service pulls in the proxy unit: %s", d)
		}
	}
}

func TestSysctlDropIn(t *testing.T) {
	settings := directives(deploymentFile(t, "99-previewd.conf"))
	if len(settings) != 1 || settings[0] != "-kernel.unprivileged_userns_clone = 1" {
		t.Errorf("settings = %q; want only the (failure-tolerant) userns knob", settings)
	}
}

// The daemon's egress filter stays closed but for loopback and the proxy's
// one address (its metrics entry point): never the proxy network, never
// any.
func TestDaemonUnitEgressAllowsOnlyTheProxyAddress(t *testing.T) {
	var allowed []string
	denyAny := false
	for _, d := range directives(deploymentFile(t, "previewd.service")) {
		if v, ok := strings.CutPrefix(d, "IPAddressAllow="); ok {
			allowed = append(allowed, v)
		}
		denyAny = denyAny || d == "IPAddressDeny=any"
	}
	if !denyAny || strings.Join(allowed, ",") != "localhost,172.30.255.2/32" {
		t.Errorf("deny any %v, allowed %v; want deny any, then localhost and 172.30.255.2/32 only", denyAny, allowed)
	}
}

// The CI companions (V1.2 spec 3.4) keep the trigger token off every
// command line, never trace the shell, call no third-party action and name
// no public image: what a runner shows or pulls never carries the token or
// leaves the site.
func TestCICompanionsKeepTheTokenOffTheRunner(t *testing.T) {
	for _, name := range []string{"ci/github-action/action.yml", "ci/gitlab-component/templates/deploy.yml"} {
		var code []string // the file without its comments, which document the usage
		for line := range strings.SplitSeq(deploymentFile(t, name), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				code = append(code, line)
			}
		}
		f := strings.Join(code, "\n")
		for _, want := range []string{"--config -", `"Authorization: Bearer %s"`, "--proto '=https'", "set -eu", "pull_request"} {
			if !strings.Contains(f, want) {
				t.Errorf("%s lacks %s", name, want)
			}
		}
		for _, forbidden := range []string{"set -x", "set -ex", "--header \"Authorization", "-H \"Authorization", "echo \"$PREVIEWD_TRIGGER_TOKEN", "uses:", "--insecure", " -k ", "commit_sha"} {
			if strings.Contains(f, forbidden) {
				t.Errorf("%s contains %q", name, forbidden)
			}
		}
	}
	gl := deploymentFile(t, "ci/gitlab-component/templates/deploy.yml")
	if !strings.Contains(gl, "image: $[[ inputs.image ]]") || !strings.Contains(gl, "name: review/$CI_COMMIT_REF_SLUG") {
		t.Error("the GitLab component must take its image from the site and record a review app")
	}
}
