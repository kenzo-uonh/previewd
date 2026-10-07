package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/proxy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
)

func TestContainerSpecMountsSecretsReadOnlyWithoutEnv(t *testing.T) {
	env := Environment{ID: "pr-7", Image: "pr-7:latest", Port: 8080, Domain: "local.previewd", SecretsDir: "/run/previewd/secrets/pr-7"}

	cfg, hostCfg, err := containerSpec(env)
	if err != nil {
		t.Fatalf("containerSpec: %v", err)
	}
	if len(cfg.Env) != 0 {
		t.Fatalf("container env must be empty, got %q", cfg.Env)
	}
	if len(cfg.Labels) != 0 {
		t.Fatalf("routing goes through route documents, never labels; got %v", cfg.Labels)
	}
	if hostCfg.NetworkMode != container.NetworkMode(networkName(env.ID)) {
		t.Fatalf("network mode = %q, want the environment's internal network only", hostCfg.NetworkMode)
	}
	if len(hostCfg.Binds) != 0 {
		t.Fatalf("legacy Binds must be unused, got %q", hostCfg.Binds)
	}
	if len(hostCfg.Mounts) != 1 {
		t.Fatalf("want exactly one mount, got %+v", hostCfg.Mounts)
	}

	m := hostCfg.Mounts[0]
	if m.Type != mount.TypeBind || m.Source != env.SecretsDir || m.Target != SecretsMountTarget {
		t.Fatalf("secrets mount = %+v, want bind %s -> %s", m, env.SecretsDir, SecretsMountTarget)
	}
	if !m.ReadOnly {
		t.Fatal("secrets mount must be read-only")
	}
	if m.BindOptions == nil || m.BindOptions.Propagation != mount.PropagationRPrivate || !m.BindOptions.NonRecursive {
		t.Fatalf("secrets mount bind options = %+v, want rprivate, non-recursive", m.BindOptions)
	}
}

func TestContainerSpecFailsClosedWithoutStagedDir(t *testing.T) {
	for _, dir := range []string{"", "relative/pr-7", "pr-7"} {
		env := Environment{ID: "pr-7", Image: "pr-7:latest", SecretsDir: dir}
		if _, _, err := containerSpec(env); err == nil {
			t.Errorf("containerSpec accepted secrets dir %q", dir)
		}
	}
}

type fakeEngine struct {
	Engine
	destroyErr error
	calls      *[]string
}

func (f fakeEngine) Destroy(context.Context, string) error {
	*f.calls = append(*f.calls, "destroy")
	return f.destroyErr
}

type fakeStager struct {
	removeErr error
	calls     *[]string
}

func (f fakeStager) Stage(string, map[string]string) (string, error) { return "", nil }

func (f fakeStager) Remove(string) error {
	*f.calls = append(*f.calls, "remove-secrets")
	return f.removeErr
}

type fakeRoutes struct {
	removeErr error
	calls     *[]string
}

func (f fakeRoutes) Publish(proxy.Route) error { return nil }

func (f fakeRoutes) Remove(string) error {
	*f.calls = append(*f.calls, "remove-route")
	return f.removeErr
}

// Teardown stops routing first, then destroys the container, then removes
// the staged secrets, and runs every step whatever fails before it.
func TestTeardownOrderAndErrorsInEveryCombination(t *testing.T) {
	routeErr := errors.New("routes dir read-only")
	destroyErr := errors.New("daemon down")
	removeErr := errors.New("busy")

	for mask := range 8 {
		var rErr, dErr, sErr error
		var want []error
		if mask&1 != 0 {
			rErr = routeErr
			want = append(want, routeErr)
		}
		if mask&2 != 0 {
			dErr = destroyErr
			want = append(want, destroyErr)
		}
		if mask&4 != 0 {
			sErr = removeErr
			want = append(want, removeErr)
		}
		t.Run(fmt.Sprintf("failures=%03b", mask), func(t *testing.T) {
			var calls []string
			err := Teardown(context.Background(),
				fakeEngine{destroyErr: dErr, calls: &calls},
				fakeRoutes{removeErr: rErr, calls: &calls},
				fakeStager{removeErr: sErr, calls: &calls},
				"pr-7")

			if strings.Join(calls, ",") != "remove-route,destroy,remove-secrets" {
				t.Fatalf("calls = %v, want [remove-route destroy remove-secrets]", calls)
			}
			if len(want) == 0 && err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			for _, w := range want {
				if !errors.Is(err, w) {
					t.Fatalf("Teardown error %v does not wrap %v", err, w)
				}
			}
		})
	}
}

func cleanProxy() container.InspectResponse {
	return container.InspectResponse{
		State:      &container.State{Running: true},
		HostConfig: &container.HostConfig{},
		Config: &container.Config{
			Cmd: []string{"--configFile=/etc/traefik/traefik.yml"},
			Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		},
		Mounts: []container.MountPoint{
			{Type: mount.TypeBind, Source: "/srv/previewd/deployments/traefik.yml", Destination: "/etc/traefik/traefik.yml"},
			{Type: mount.TypeBind, Source: "/var/lib/previewd/routes", Destination: "/etc/traefik/routes"},
		},
	}
}

func TestCheckProxyContainerAcceptsFileProviderOnly(t *testing.T) {
	if err := checkProxyContainer("traefik-proxy", cleanProxy()); err != nil {
		t.Fatalf("clean proxy refused: %v", err)
	}
}

// Fail closed: any path from the proxy to a daemon, or a proxy that is not
// running, refuses to start previewd.
func TestCheckProxyContainerFailsClosed(t *testing.T) {
	cases := map[string]func(c *container.InspectResponse){
		"no state":    func(c *container.InspectResponse) { c.State = nil },
		"not running": func(c *container.InspectResponse) { c.State.Running = false },
		"privileged":  func(c *container.InspectResponse) { c.HostConfig.Privileged = true },
		"docker socket": func(c *container.InspectResponse) {
			c.Mounts = append(c.Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"})
		},
		"socket renamed in container": func(c *container.InspectResponse) {
			c.Mounts = append(c.Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/run/docker.sock", Destination: "/tmp/d"})
		},
		"containerd socket": func(c *container.InspectResponse) {
			c.Mounts = append(c.Mounts, container.MountPoint{Type: mount.TypeBind, Source: "/srv/x", Destination: "/run/containerd/containerd.sock"})
		},
		"docker provider flag": func(c *container.InspectResponse) {
			c.Config.Cmd = append(c.Config.Cmd, "--providers.docker=true")
		},
		"docker provider flag mixed case": func(c *container.InspectResponse) {
			c.Args = append(c.Args, "--Providers.Docker.Endpoint=tcp://10.0.0.1:2375")
		},
		"docker provider env": func(c *container.InspectResponse) {
			c.Config.Env = append(c.Config.Env, "TRAEFIK_PROVIDERS_DOCKER=true")
		},
		"docker provider env lower case": func(c *container.InspectResponse) {
			c.Config.Env = append(c.Config.Env, "traefik_providers_docker_endpoint=tcp://10.0.0.1:2375")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := cleanProxy()
			mutate(&c)
			if err := checkProxyContainer("traefik-proxy", c); err == nil {
				t.Fatal("proxy accepted")
			}
		})
	}
}

func TestBackendAddr(t *testing.T) {
	const netName = "pr-7-0123456789-net"
	ip := netip.MustParseAddr("172.31.4.2")
	withIP := func(a netip.Addr) container.InspectResponse {
		return container.InspectResponse{
			Name: "/pr-7",
			NetworkSettings: &container.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{netName: {IPAddress: a}},
			},
		}
	}

	got, err := backendAddr(withIP(ip), netName, 8080)
	if err != nil || got != netip.AddrPortFrom(ip, 8080) {
		t.Fatalf("backendAddr = %v, %v; want %v", got, err, netip.AddrPortFrom(ip, 8080))
	}

	bad := map[string]struct {
		c    container.InspectResponse
		net  string
		port int
	}{
		"port 0":           {withIP(ip), netName, 0},
		"port too large":   {withIP(ip), netName, 65536},
		"negative port":    {withIP(ip), netName, -1},
		"no settings":      {container.InspectResponse{Name: "/pr-7"}, netName, 8080},
		"other network":    {withIP(ip), "previewd-proxy", 8080},
		"no address":       {withIP(netip.Addr{}), netName, 8080},
		"unspecified addr": {withIP(netip.IPv4Unspecified()), netName, 8080},
		"nil endpoint":     {container.InspectResponse{Name: "/pr-7", NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{netName: nil}}}, netName, 8080},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			if got, err := backendAddr(tc.c, tc.net, tc.port); err == nil {
				t.Fatalf("backendAddr accepted: %v", got)
			}
		})
	}
}
