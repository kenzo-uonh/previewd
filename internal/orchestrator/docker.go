package orchestrator

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// SecretsMountTarget is where an environment's staged secrets appear inside
// its container, one read-only file per key.
const SecretsMountTarget = "/run/secrets"

// Limits bound every PR container.
type Limits struct {
	MemoryBytes int64 // hard limit; swap is disabled (MemorySwap = MemoryBytes)
	Pids        int64 // maximum number of tasks
}

func (l Limits) validate() error {
	if l.MemoryBytes <= 0 || l.Pids <= 0 {
		return fmt.Errorf("container limits must be positive (memory %d bytes, pids %d)", l.MemoryBytes, l.Pids)
	}
	return nil
}

// DockerEngine implements Engine using the local Docker API.
type DockerEngine struct {
	client *client.Client
	// proxyContainer is the Traefik container. It joins each environment's
	// internal network so that it, and only it, reaches the environment.
	proxyContainer string
	limits         Limits
}

// NewDockerEngine initializes a connection to the local host's Docker daemon.
// proxyContainer names the Traefik container that serves the routes; limits
// bound every PR container.
func NewDockerEngine(proxyContainer string, limits Limits) (*DockerEngine, error) {
	if proxyContainer == "" {
		return nil, errors.New("proxy container name is required")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize docker client: %w", err)
	}
	return &DockerEngine{client: cli, proxyContainer: proxyContainer, limits: limits}, nil
}

// networkName is the internal bridge network of envID.
func networkName(envID string) string {
	return envID + "-net"
}

// VerifyProxy refuses a proxy container that is missing, stopped, or able
// to reach the Docker daemon (see checkProxyContainer).
func (d *DockerEngine) VerifyProxy(ctx context.Context) error {
	res, err := d.client.ContainerInspect(ctx, d.proxyContainer, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect proxy container %s: %w", d.proxyContainer, err)
	}
	return checkProxyContainer(d.proxyContainer, res.Container)
}

// checkProxyContainer fails closed unless the proxy runs without any path to
// the Docker daemon: no mounted socket (a socket gives the proxy host root),
// no Docker provider in its arguments or environment (PR containers could
// then set routes through labels), not privileged.
func checkProxyContainer(name string, c container.InspectResponse) error {
	if c.State == nil || !c.State.Running {
		return fmt.Errorf("proxy container %s is not running", name)
	}
	if c.HostConfig != nil && c.HostConfig.Privileged {
		return fmt.Errorf("proxy container %s is privileged", name)
	}
	for _, m := range c.Mounts {
		if strings.HasSuffix(m.Source, ".sock") || strings.HasSuffix(m.Destination, ".sock") {
			return fmt.Errorf("proxy container %s mounts socket %s: the proxy must never reach a daemon", name, m.Destination)
		}
	}
	if c.Config != nil {
		for _, kv := range c.Config.Env {
			if strings.HasPrefix(strings.ToUpper(kv), "TRAEFIK_PROVIDERS_DOCKER") {
				return fmt.Errorf("proxy container %s enables the Docker provider through its environment", name)
			}
		}
	}
	args := c.Args
	if c.Config != nil {
		args = append(append([]string{}, c.Config.Cmd...), args...)
	}
	for _, a := range args {
		if strings.Contains(strings.ToLower(a), "providers.docker") {
			return fmt.Errorf("proxy container %s enables the Docker provider: %s", name, a)
		}
	}
	return nil
}

// Ping verifies daemon reachability.
func (d *DockerEngine) Ping(ctx context.Context) error {
	if _, err := d.client.Ping(ctx, client.PingOptions{}); err != nil {
		return fmt.Errorf("docker daemon ping failed: %w", err)
	}
	return nil
}

// Build creates an in-memory tarball of the context directory and streams it to the Docker daemon.
func (d *DockerEngine) Build(ctx context.Context, buildDir, tag string) error {
	tarBuffer := new(bytes.Buffer)
	tw := tar.NewWriter(tarBuffer)
	defer func() {
		_ = tw.Close()
	}()

	root, err := os.OpenRoot(buildDir)
	if err != nil {
		return fmt.Errorf("failed to open secure root for build directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	err = fs.WalkDir(root.FS(), ".", func(path string, dEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}

		info, err := dEntry.Info()
		if err != nil {
			return fmt.Errorf("failed to retrieve file info: %w", err)
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return fmt.Errorf("failed to create tar header: %w", err)
		}
		header.Name = filepath.ToSlash(path)

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header: %w", err)
		}

		if dEntry.IsDir() {
			return nil
		}

		file, err := root.Open(path)
		if err != nil {
			return fmt.Errorf("failed to securely open file for tar: %w", err)
		}
		defer func() {
			_ = file.Close()
		}()

		if _, err := io.Copy(tw, file); err != nil {
			return fmt.Errorf("failed to copy file contents to tar: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("tar context creation failed: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar writer close failure: %w", err)
	}

	opts := client.ImageBuildOptions{
		Dockerfile: "Dockerfile",
		Tags:       []string{tag},
		Remove:     true,
	}

	res, err := d.client.ImageBuild(ctx, bytes.NewReader(tarBuffer.Bytes()), opts)
	if err != nil {
		return fmt.Errorf("docker image build failed: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		return fmt.Errorf("failed to drain build output: %w", err)
	}

	return nil
}

// ProvisionNetwork creates the environment's internal bridge network: no
// default route, no egress, shared only with the proxy. An existing network
// of that name is reused only if it is internal.
func (d *DockerEngine) ProvisionNetwork(ctx context.Context, envID string) error {
	netName := networkName(envID)
	opts := client.NetworkCreateOptions{
		Driver:   "bridge",
		Internal: true,
	}
	_, err := d.client.NetworkCreate(ctx, netName, opts)
	if err == nil {
		return nil
	}
	if !errdefs.IsConflict(err) {
		return fmt.Errorf("failed to provision isolated network %s: %w", netName, err)
	}
	res, inspectErr := d.client.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if inspectErr != nil {
		return fmt.Errorf("inspect existing network %s: %w", netName, inspectErr)
	}
	if !res.Network.Internal {
		return fmt.Errorf("existing network %s is not internal: refusing to reuse it", netName)
	}
	return nil
}

// containerSpec builds the container configuration for env. Secrets are never
// part of it: the container receives the host directory staged on ramfs as a
// read-only bind mount, so no secret value reaches the Docker API, the
// daemon's on-disk container config, or `docker inspect`.
//
// The PR's code is hostile: no capability, no privilege gain through setuid
// or file capabilities, a read-only root file system with no writable mount
// at all, bounded memory without swap (what the application reads from its
// secrets never reaches swap) and a bounded task count.
func containerSpec(env Environment, limits Limits) (*container.Config, *container.HostConfig, error) {
	if env.SecretsDir == "" || !filepath.IsAbs(env.SecretsDir) {
		return nil, nil, fmt.Errorf("environment %s: staged secrets dir %q must be an absolute path", env.ID, env.SecretsDir)
	}
	if err := limits.validate(); err != nil {
		return nil, nil, fmt.Errorf("environment %s: %w", env.ID, err)
	}
	pids := limits.Pids

	// No routing labels: the proxy reads route documents, never labels.
	cfg := &container.Config{
		Image: env.Image,
	}

	netName := networkName(env.ID)
	hostCfg := &container.HostConfig{
		NetworkMode:    container.NetworkMode(netName),
		AutoRemove:     false,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: true,
		Resources: container.Resources{
			Memory:     limits.MemoryBytes,
			MemorySwap: limits.MemoryBytes,
			PidsLimit:  &pids,
		},
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   env.SecretsDir,
				Target:   SecretsMountTarget,
				ReadOnly: true,
				BindOptions: &mount.BindOptions{
					// Never pick up mounts made under the staging dir later.
					Propagation:  mount.PropagationRPrivate,
					NonRecursive: true,
				},
			},
		},
	}
	return cfg, hostCfg, nil
}

// Deploy starts the environment's container on its internal network only,
// joins the proxy to that network, and returns the address the route
// document points to.
func (d *DockerEngine) Deploy(ctx context.Context, env Environment) (netip.AddrPort, error) {
	cfg, hostCfg, err := containerSpec(env, d.limits)
	if err != nil {
		return netip.AddrPort{}, err
	}

	resp, err := d.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     cfg,
		HostConfig: hostCfg,
		Name:       env.ID,
	})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to create environment container %s: %w", env.ID, err)
	}

	if _, err := d.client.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to start environment container %s: %w", env.ID, err)
	}

	// The proxy can be recreated while the daemon runs: re-check it before
	// joining it to another environment's network.
	if err := d.VerifyProxy(ctx); err != nil {
		return netip.AddrPort{}, err
	}
	netName := networkName(env.ID)
	if err := d.connectProxy(ctx, netName); err != nil {
		return netip.AddrPort{}, err
	}

	res, err := d.client.ContainerInspect(ctx, resp.ID, client.ContainerInspectOptions{})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("inspect environment container %s: %w", env.ID, err)
	}
	return backendAddr(res.Container, netName, env.Port)
}

// connectProxy joins the proxy container to netName. Already joined is fine.
func (d *DockerEngine) connectProxy(ctx context.Context, netName string) error {
	_, err := d.client.NetworkConnect(ctx, netName, client.NetworkConnectOptions{Container: d.proxyContainer})
	if err == nil {
		return nil
	}
	attached, inspectErr := d.proxyAttached(ctx, netName)
	if inspectErr != nil {
		return errors.Join(fmt.Errorf("connect proxy to %s: %w", netName, err), inspectErr)
	}
	if !attached {
		return fmt.Errorf("connect proxy to %s: %w", netName, err)
	}
	return nil
}

// proxyAttached reports whether the proxy container is an endpoint of netName.
func (d *DockerEngine) proxyAttached(ctx context.Context, netName string) (bool, error) {
	res, err := d.client.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if err != nil {
		return false, fmt.Errorf("inspect network %s: %w", netName, err)
	}
	for id, ep := range res.Network.Containers {
		if ep.Name == d.proxyContainer || id == d.proxyContainer {
			return true, nil
		}
	}
	return false, nil
}

// backendAddr is the container's address on its internal network, with the
// application port.
func backendAddr(c container.InspectResponse, netName string, port int) (netip.AddrPort, error) {
	if port <= 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("application port %d out of range", port)
	}
	if c.NetworkSettings == nil {
		return netip.AddrPort{}, fmt.Errorf("container %s has no network settings", c.Name)
	}
	ep, ok := c.NetworkSettings.Networks[netName]
	if !ok || ep == nil {
		return netip.AddrPort{}, fmt.Errorf("container %s is not attached to %s", c.Name, netName)
	}
	if !ep.IPAddress.IsValid() || ep.IPAddress.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("container %s has no address on %s", c.Name, netName)
	}
	return netip.AddrPortFrom(ep.IPAddress, uint16(port)), nil // #nosec G115 -- port checked within 1..65535 above
}

// Destroy aggressively terminates the container, purges the image, and removes the network.
func (d *DockerEngine) Destroy(ctx context.Context, id string) error {
	opts := client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}
	if _, err := d.client.ContainerRemove(ctx, id, opts); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("container teardown failed: %w", err)
	}

	netName := networkName(id)
	if err := d.disconnectProxy(ctx, netName); err != nil {
		return err
	}
	if _, err := d.client.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("network teardown failed: %w", err)
	}

	imgName := fmt.Sprintf("%s:latest", id)
	if _, err := d.client.ImageRemove(ctx, imgName, client.ImageRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("image teardown failed: %w", err)
	}

	return nil
}

// disconnectProxy detaches the proxy from netName, which cannot be removed
// while the proxy is an endpoint. A missing network or a proxy already
// detached is fine.
func (d *DockerEngine) disconnectProxy(ctx context.Context, netName string) error {
	_, err := d.client.NetworkDisconnect(ctx, netName, client.NetworkDisconnectOptions{Container: d.proxyContainer, Force: true})
	if err == nil || errdefs.IsNotFound(err) {
		return nil
	}
	attached, inspectErr := d.proxyAttached(ctx, netName)
	if inspectErr != nil {
		if errdefs.IsNotFound(inspectErr) {
			return nil
		}
		return errors.Join(fmt.Errorf("disconnect proxy from %s: %w", netName, err), inspectErr)
	}
	if attached {
		return fmt.Errorf("disconnect proxy from %s: %w", netName, err)
	}
	return nil
}

// Logs returns the standard output and error streams.
func (d *DockerEngine) Logs(ctx context.Context, id string) (io.ReadCloser, error) {
	opts := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	}
	logs, err := d.client.ContainerLogs(ctx, id, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to stream logs for environment %s: %w", id, err)
	}
	return logs, nil
}

// Close gracefully terminates the SDK connection.
func (d *DockerEngine) Close() error {
	return d.client.Close()
}
