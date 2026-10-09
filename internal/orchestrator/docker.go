package orchestrator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/textutil"
	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// SecretsMountTarget is where an environment's staged secrets appear inside
// its container, one read-only file per key.
const SecretsMountTarget = "/run/secrets"

// Ownership labels on the containers and networks previewd creates. They
// carry identities only, are set by previewd on every create (overriding any
// image label of the same key), and are read by Observe at startup. Traefik
// reads no label.
const (
	LabelEnv = "previewd.env"
	LabelJob = "previewd.job"
)

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

// buildOptions is the only /build request previewd sends (V1 F2, D-V1-2):
// BuildKit, which forces NetworkMode "none" on every RUN of the build; no
// pull of the parent; no cache, so no state of another PR's build is reused;
// intermediate containers removed, on failure too; the ownership labels,
// which override any label the Dockerfile sets. It carries no build
// argument (BUILDKIT_SYNTAX would select a frontend image), no session, no
// remote context, no registry credential, and no per-build memory, CPU or
// cgroup parent: BuildKit ignores them (D-V1-4).
func buildOptions(spec BuildSpec) (client.ImageBuildOptions, error) {
	if !envid.Valid(spec.EnvID) {
		return client.ImageBuildOptions{}, fmt.Errorf("build: invalid environment ID %q", textutil.Truncate(spec.EnvID, maxBuildErrorBytes))
	}
	if spec.Tag != spec.EnvID+":latest" {
		return client.ImageBuildOptions{}, fmt.Errorf("build %s: tag %q is not %s:latest", spec.EnvID, textutil.Truncate(spec.Tag, maxBuildErrorBytes), spec.EnvID)
	}
	if spec.JobID <= 0 {
		return client.ImageBuildOptions{}, fmt.Errorf("build %s: job ID %d is not positive", spec.EnvID, spec.JobID)
	}
	if spec.ContextTar == nil {
		return client.ImageBuildOptions{}, fmt.Errorf("build %s: no build context", spec.EnvID)
	}
	return client.ImageBuildOptions{
		Version:     build.BuilderBuildKit,
		Dockerfile:  dockerfileName,
		Tags:        []string{spec.Tag},
		NetworkMode: string(network.NetworkNone),
		PullParent:  false,
		NoCache:     true,
		Remove:      true,
		ForceRemove: true,
		Labels: map[string]string{
			LabelEnv: spec.EnvID,
			LabelJob: strconv.FormatInt(spec.JobID, 10),
		},
	}, nil
}

// Build streams spec.ContextTar to the daemon as the /build request body
// and reads the response stream to its end. The daemon answers 200 before
// building: the outcome is in the stream (readBuildStream).
func (d *DockerEngine) Build(ctx context.Context, spec BuildSpec) error {
	opts, err := buildOptions(spec)
	if err != nil {
		return err
	}
	res, err := d.client.ImageBuild(ctx, spec.ContextTar, opts)
	if err != nil {
		return fmt.Errorf("docker image build failed: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if _, err := readBuildStream(res.Body); err != nil {
		return fmt.Errorf("docker image build: %w", err)
	}
	return nil
}

// VerifyBaseImages refuses every allowlisted base image (canonical
// name:tag@sha256:<digest> references, validate.AllowedBaseImages) whose
// local name:tag record is missing or is not the pinned digest, or that
// carries ONBUILD triggers: the daemon would run them in the PR's build,
// where the preflight cannot see them. The daemon builds an allowlisted
// base offline only from that local record (validate.BaseImage); previewd
// never pulls, base images are loaded by the operator.
func (d *DockerEngine) VerifyBaseImages(ctx context.Context, allowed map[string]bool) error {
	if len(allowed) == 0 {
		return errors.New("no base image allowed")
	}
	for _, ref := range slices.Sorted(maps.Keys(allowed)) {
		nameTag, _, err := validate.SplitBaseImage(ref)
		if err != nil {
			return fmt.Errorf("base image %s: %w", ref, err)
		}
		res, err := d.client.ImageInspect(ctx, nameTag)
		if err != nil {
			return fmt.Errorf("base image %s is not loaded on the host as %s (previewd never pulls): %w", ref, nameTag, err)
		}
		if err := checkBaseImage(ref, res.InspectResponse); err != nil {
			return err
		}
	}
	return nil
}

// checkBaseImage fails closed unless img, the local record of ref's
// name:tag, is ref's digest (its ID or a repository digest of the same
// name) and has no ONBUILD trigger.
func checkBaseImage(ref string, img image.InspectResponse) error {
	nameTag, dgst, err := validate.SplitBaseImage(ref)
	if err != nil {
		return fmt.Errorf("base image %s: %w", ref, err)
	}
	named, err := reference.ParseNormalizedNamed(nameTag)
	if err != nil {
		return fmt.Errorf("base image %s: %w", ref, err)
	}
	name := named.Name()
	pinned := img.ID == dgst
	for _, rd := range img.RepoDigests {
		if n, err := reference.ParseNormalizedNamed(rd); err == nil {
			if c, ok := n.(reference.Canonical); ok && c.Name() == name && c.Digest().String() == dgst {
				pinned = true
			}
		}
	}
	if !pinned {
		return fmt.Errorf("base image %s: the local %s is another image (ID %s)", ref, nameTag, textutil.Truncate(img.ID, 80))
	}
	if img.Config != nil && len(img.Config.OnBuild) > 0 {
		return fmt.Errorf("base image %s carries %d ONBUILD trigger(s): refused, they would run in every PR build", ref, len(img.Config.OnBuild))
	}
	return nil
}

// ErrBuildFailed is a build the daemon reported as failed, or whose outcome
// it never confirmed.
var ErrBuildFailed = errors.New("build failed")

const (
	// maxBuildMessageBytes bounds one line of the build stream, its newline
	// included; a longer line fails the build rather than being cut.
	maxBuildMessageBytes = 1 << 20
	// maxBuildErrorBytes bounds the daemon's error text quoted in our error:
	// it repeats PR-controlled Dockerfile content.
	maxBuildErrorBytes = 512
)

// buildMessage is one line of the /build response: newline-delimited JSON
// from the classic builder and from BuildKit alike.
type buildMessage struct {
	ID          string          `json:"id"`
	Aux         json.RawMessage `json:"aux"`
	Error       string          `json:"error"`
	ErrorDetail *struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

// readBuildStream reads the build response to its end and returns the built
// image ID. A build is successful only if no message carries an error and
// the daemon reported the image ID (classic: {"aux":{"ID":...}}; BuildKit:
// {"id":"moby.image.id","aux":{"ID":...}}). An error message, a malformed or
// oversized line, a stream cut short, or a stream without the image ID fails
// the build (ErrBuildFailed or a read error).
func readBuildStream(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxBuildMessageBytes)
	imageID := ""
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg buildMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			return "", fmt.Errorf("%w: malformed build output line: %w", ErrBuildFailed, err)
		}
		if msg.Error != "" || msg.ErrorDetail != nil {
			detail := msg.Error
			if msg.ErrorDetail != nil && msg.ErrorDetail.Message != "" {
				detail = msg.ErrorDetail.Message
			}
			return "", fmt.Errorf("%w: %q", ErrBuildFailed, textutil.Truncate(detail, maxBuildErrorBytes))
		}
		if id, ok := auxImageID(msg); ok {
			imageID = id
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("%w: read build output: %w", ErrBuildFailed, err)
	}
	if imageID == "" {
		return "", fmt.Errorf("%w: the daemon did not report an image ID", ErrBuildFailed)
	}
	return imageID, nil
}

// auxImageID extracts the image ID message; other aux payloads (BuildKit
// progress traces are base64 strings) are ignored.
func auxImageID(msg buildMessage) (string, bool) {
	if len(msg.Aux) == 0 || msg.Aux[0] != '{' || (msg.ID != "" && msg.ID != "moby.image.id") {
		return "", false
	}
	var aux struct {
		ID string `json:"ID"`
	}
	if json.Unmarshal(msg.Aux, &aux) != nil || !validImageID(aux.ID) {
		return "", false
	}
	return aux.ID, true
}

func validImageID(id string) bool {
	hex, ok := strings.CutPrefix(id, "sha256:")
	if !ok || len(hex) != 64 {
		return false
	}
	for i := range len(hex) {
		if c := hex[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ProvisionNetwork creates the environment's internal bridge network: no
// default route, no egress, shared only with the proxy. An existing network
// of that name is reused only if it is internal.
func (d *DockerEngine) ProvisionNetwork(ctx context.Context, envID string) error {
	netName := networkName(envID)
	opts := client.NetworkCreateOptions{
		Driver:   "bridge",
		Internal: true,
		Labels:   map[string]string{LabelEnv: envID},
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

	// Ownership labels only: the proxy reads route documents, never labels.
	cfg := &container.Config{
		Image: env.Image,
		Labels: map[string]string{
			LabelEnv: env.ID,
			LabelJob: strconv.FormatInt(env.JobID, 10),
		},
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

// Observe reports, per environment, the containers and networks previewd
// owns on the host: by ownership label, or by name for resources created
// before labels existed (container <env-id>, network <env-id>-net).
func (d *DockerEngine) Observe(ctx context.Context) (map[string]EngineState, error) {
	containers, err := d.client.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	networks, err := d.client.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	return observe(containers.Items, networks.Items), nil
}

// observe groups owned containers and networks by environment.
func observe(containers []container.Summary, networks []network.Summary) map[string]EngineState {
	states := map[string]EngineState{}
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		env := ownerOf(c.Labels, name)
		if env == "" {
			continue
		}
		st := states[env]
		st.Running = st.Running || c.State == container.StateRunning
		st.Containers++
		if job, err := strconv.ParseInt(c.Labels[LabelJob], 10, 64); err == nil && job > 0 && name == env {
			st.JobID = job
		}
		states[env] = st
	}
	for _, n := range networks {
		env := ownerOf(n.Labels, strings.TrimSuffix(n.Name, "-net"))
		if env == "" || n.Name != networkName(env) {
			continue
		}
		st := states[env]
		st.NetworkBound = true
		states[env] = st
	}
	return states
}

// ownerOf is the environment a resource belongs to: its ownership label if
// set, else its name if that is an environment ID; "" if neither is valid.
func ownerOf(labels map[string]string, name string) string {
	if env, ok := labels[LabelEnv]; ok {
		if envid.Valid(env) {
			return env
		}
		return ""
	}
	if envid.Valid(name) {
		return name
	}
	return ""
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
