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
	"math"
	"net/netip"
	"os"
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
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
)

// SecretsMountTarget is where an environment's staged secrets appear inside
// its container, one read-only file per key.
const SecretsMountTarget = "/run/secrets"

// Ownership labels on the containers, networks and volumes previewd creates. They
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
	// dataRoot is PREVIEWD_DOCKER_DATA_ROOT, whose file system FreeDisk
	// measures with statDisk; "" reads the daemon's DockerRootDir at each
	// call.
	dataRoot string
	statDisk DiskStat
}

// DiskStat is the free space, in bytes, of the file system holding a clean
// absolute path (hardening.FreeDiskBytes, injected by main).
type DiskStat func(path string) (int64, error)

// NewDockerEngine initializes a connection to the local host's Docker daemon.
// proxyContainer names the Traefik container that serves the routes; limits
// bound every PR container; dataRoot is the daemon's data root ("" to ask
// the daemon), a clean absolute path otherwise, measured by statDisk.
func NewDockerEngine(proxyContainer string, limits Limits, dataRoot string, statDisk DiskStat) (*DockerEngine, error) {
	if proxyContainer == "" {
		return nil, errors.New("proxy container name is required")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if dataRoot != "" && (!filepath.IsAbs(dataRoot) || dataRoot != filepath.Clean(dataRoot)) {
		return nil, fmt.Errorf("docker data root %q is not a clean absolute path", dataRoot)
	}
	if statDisk == nil {
		return nil, errors.New("a free-disk probe is required")
	}
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize docker client: %w", err)
	}
	return &DockerEngine{client: cli, proxyContainer: proxyContainer, limits: limits, dataRoot: dataRoot, statDisk: statDisk}, nil
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
	return lockedBuildOptions(spec.Tag, map[string]string{
		LabelEnv: spec.EnvID,
		LabelJob: strconv.FormatInt(spec.JobID, 10),
	}), nil
}

// lockedBuildOptions is the request every build sends, PR builds and the
// startup build probe alike, so the probe proves the request PRs get.
func lockedBuildOptions(tag string, labels map[string]string) client.ImageBuildOptions {
	return client.ImageBuildOptions{
		Version:     build.BuilderBuildKit,
		Dockerfile:  dockerfileName,
		Tags:        []string{tag},
		NetworkMode: string(network.NetworkNone),
		PullParent:  false,
		NoCache:     true,
		Remove:      true,
		ForceRemove: true,
		Labels:      labels,
	}
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
			CgroupParent: EnvCgroupParent,
			Memory:       limits.MemoryBytes,
			MemorySwap:   limits.MemoryBytes,
			PidsLimit:    &pids,
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
	if env.Compose != nil {
		// Non-secret settings of the PR's compose file: its secrets travel by
		// the ramfs mount only.
		cfg.Env = slices.Clone(env.Compose.Primary.Env)
		cfg.Cmd = slices.Clone(env.Compose.Primary.Command)
		hostCfg.Mounts = append(hostCfg.Mounts, volumeMounts(env.ID, env.Compose.Primary.Mounts)...)
	}
	return cfg, hostCfg, nil
}

// sidecarCaps is what the official database and cache images need at start:
// their entrypoint, running as root inside the container, owns the data
// directory and drops to the service's own user. Every other capability is
// dropped, and no-new-privileges stays set.
var sidecarCaps = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}

// sidecarTmpfsBytes bounds each tmpfs of a sidecar; it counts against the
// container's memory limit.
const sidecarTmpfsBytes = 64 << 20

// volumeName is the daemon-wide name of the volume vol of envID.
func volumeName(envID, vol string) string { return "previewd-" + envID + "-" + vol }

// sidecarName is the container name of the sidecar svc of envID (the
// primary is named envID itself).
func sidecarName(envID, svc string) string { return envID + "-" + svc }

func volumeMounts(envID string, mounts []ComposeMount) []mount.Mount {
	out := make([]mount.Mount, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, mount.Mount{Type: mount.TypeVolume, Source: volumeName(envID, m.Volume), Target: m.Target, ReadOnly: m.ReadOnly})
	}
	return out
}

// endpointAlias attaches a container to the environment network under its
// service name, so that the services reach one another by it. The network is
// per environment: an alias never collides across environments.
func endpointAlias(envID, svc string) *network.NetworkingConfig {
	return &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
		networkName(envID): {Aliases: []string{svc}},
	}}
}

// sidecarSpec builds the container configuration of a sidecar of env. imageID
// is the ID of the verified local image, never a name a registry could
// answer. A sidecar gets what the primary gets (the environment's internal
// network only, no privilege gain, a read-only root file system, bounded
// memory without swap and task count) and none of what the primary is given:
// no secrets mount, no host path, no published port. Its writable state is
// its named volumes and two bounded tmpfs.
func sidecarSpec(env Environment, svc ComposeService, imageID string, limits Limits) (*container.Config, *container.HostConfig, error) {
	if !envid.Valid(env.ID) {
		return nil, nil, fmt.Errorf("sidecar %s: invalid environment ID %q", svc.Name, textutil.Truncate(env.ID, maxBuildErrorBytes))
	}
	if imageID == "" {
		return nil, nil, fmt.Errorf("environment %s: sidecar %s has no verified image", env.ID, svc.Name)
	}
	if err := limits.validate(); err != nil {
		return nil, nil, fmt.Errorf("environment %s: %w", env.ID, err)
	}
	pids := limits.Pids
	cfg := &container.Config{
		Image: imageID,
		Env:   slices.Clone(svc.Env),
		Cmd:   slices.Clone(svc.Command),
		Labels: map[string]string{
			LabelEnv: env.ID,
			LabelJob: strconv.FormatInt(env.JobID, 10),
		},
	}
	tmpfs := func(target string, mode os.FileMode) mount.Mount {
		return mount.Mount{Type: mount.TypeTmpfs, Target: target, TmpfsOptions: &mount.TmpfsOptions{
			SizeBytes: sidecarTmpfsBytes, Mode: mode, Options: [][]string{{"nosuid"}, {"nodev"}},
		}}
	}
	hostCfg := &container.HostConfig{
		NetworkMode:    container.NetworkMode(networkName(env.ID)),
		AutoRemove:     false,
		CapDrop:        []string{"ALL"},
		CapAdd:         slices.Clone(sidecarCaps),
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: true,
		Resources: container.Resources{
			CgroupParent: EnvCgroupParent,
			Memory:       limits.MemoryBytes,
			MemorySwap:   limits.MemoryBytes,
			PidsLimit:    &pids,
		},
		Mounts: append([]mount.Mount{tmpfs("/tmp", 0o1777), tmpfs("/run", 0o755)}, volumeMounts(env.ID, svc.Mounts)...),
	}
	return cfg, hostCfg, nil
}

// EnvCgroupParent is the cgroup parent of every environment container,
// named rather than left to the daemon: the BuildKit drop-in
// (deployments/docker.service.d/previewd-builds.conf) makes the daemon's
// default parent the build slice, and an environment there would share the
// builds' limits and leave the subtree busy, which the startup build probe
// refuses (D-V1-4). system.slice is the systemd driver's own default; with
// the cgroupfs driver it is a plain directory.
const EnvCgroupParent = "system.slice"

// Deploy starts the environment on its internal network only, joins the
// proxy to that network, and returns the address the route document points
// to. With env.Compose, the sidecars start first (their images verified on
// the host, their named volumes created and checked), then the primary.
func (d *DockerEngine) Deploy(ctx context.Context, env Environment) (netip.AddrPort, error) {
	cfg, hostCfg, err := containerSpec(env, d.limits)
	if err != nil {
		return netip.AddrPort{}, err
	}
	createOpts := client.ContainerCreateOptions{Config: cfg, HostConfig: hostCfg, Name: env.ID}
	if env.Compose != nil {
		if err := d.startSidecars(ctx, env); err != nil {
			return netip.AddrPort{}, err
		}
		createOpts.NetworkingConfig = endpointAlias(env.ID, env.Compose.Primary.Name)
	}

	resp, err := d.client.ContainerCreate(ctx, createOpts)
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

// startSidecars verifies every sidecar image on the host, creates the
// environment's volumes, then creates and starts each sidecar. Nothing
// reaches the daemon before every image is verified, and nothing is pulled.
// A failure leaves what was created for Destroy (the reconciler's rollback,
// or the startup sweep) to remove by ownership label.
func (d *DockerEngine) startSidecars(ctx context.Context, env Environment) error {
	type planned struct {
		name string
		cfg  *container.Config
		host *container.HostConfig
		svc  ComposeService
	}
	plan := make([]planned, 0, len(env.Compose.Sidecars))
	for _, svc := range env.Compose.Sidecars {
		imageID, err := d.resolveSidecarImage(ctx, svc.Image)
		if err != nil {
			return fmt.Errorf("sidecar %s: %w", svc.Name, err)
		}
		cfg, host, err := sidecarSpec(env, svc, imageID, d.limits)
		if err != nil {
			return err
		}
		plan = append(plan, planned{sidecarName(env.ID, svc.Name), cfg, host, svc})
	}
	if err := d.createVolumes(ctx, env); err != nil {
		return err
	}
	for _, p := range plan {
		resp, err := d.client.ContainerCreate(ctx, client.ContainerCreateOptions{
			Config: p.cfg, HostConfig: p.host, Name: p.name, NetworkingConfig: endpointAlias(env.ID, p.svc.Name),
		})
		if err != nil {
			return fmt.Errorf("failed to create sidecar container %s: %w", p.name, err)
		}
		if _, err := d.client.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
			return fmt.Errorf("failed to start sidecar container %s: %w", p.name, err)
		}
	}
	return nil
}

// resolveSidecarImage returns the ID of the local image of ref (a canonical
// name:tag@sha256:<digest> reference of the allowlist) after the checks of a
// base image: its local name:tag is the pinned digest and it carries no
// ONBUILD trigger. The container runs that ID, so the tag moving after the
// check changes nothing. A missing image is an error: previewd never pulls.
func (d *DockerEngine) resolveSidecarImage(ctx context.Context, ref string) (string, error) {
	nameTag, _, err := validate.SplitBaseImage(ref)
	if err != nil {
		return "", fmt.Errorf("image %s: %w", textutil.Truncate(ref, maxBuildErrorBytes), err)
	}
	res, err := d.client.ImageInspect(ctx, nameTag)
	if err != nil {
		return "", fmt.Errorf("image %s is not loaded on the host as %s (previewd never pulls): %w", ref, nameTag, err)
	}
	if err := checkBaseImage(ref, res.InspectResponse); err != nil {
		return "", err
	}
	return res.ID, nil
}

// createVolumes creates the named volumes of env.Compose, labelled with the
// ownership labels, on the plain local driver without option. The daemon
// answers an existing volume of that name instead of failing: it is accepted
// only if it is ours (the label), local, and without option, since a driver
// option could make it a bind mount of a host path.
func (d *DockerEngine) createVolumes(ctx context.Context, env Environment) error {
	for _, vol := range env.Compose.Volumes {
		name := volumeName(env.ID, vol)
		res, err := d.client.VolumeCreate(ctx, client.VolumeCreateOptions{
			Name:   name,
			Driver: "local",
			Labels: map[string]string{LabelEnv: env.ID, LabelJob: strconv.FormatInt(env.JobID, 10)},
		})
		if err != nil {
			return fmt.Errorf("create volume %s: %w", name, err)
		}
		if v := res.Volume; v.Name != name || v.Driver != "local" || len(v.Options) != 0 || v.Labels[LabelEnv] != env.ID {
			return fmt.Errorf("volume %s already exists and is not previewd's plain local volume of %s: refusing to reuse it", name, env.ID)
		}
	}
	return nil
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

// Destroy aggressively terminates every container of the environment (the
// primary and its sidecars, by ownership label), removes the network, then
// the named volumes (in use until the containers are gone), and purges the
// image.
func (d *DockerEngine) Destroy(ctx context.Context, id string) error {
	if err := d.removeContainers(ctx, id); err != nil {
		return err
	}

	netName := networkName(id)
	if err := d.disconnectProxy(ctx, netName); err != nil {
		return err
	}
	if _, err := d.client.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("network teardown failed: %w", err)
	}

	if err := d.removeVolumes(ctx, id); err != nil {
		return err
	}

	imgName := fmt.Sprintf("%s:latest", id)
	if _, err := d.client.ImageRemove(ctx, imgName, client.ImageRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("image teardown failed: %w", err)
	}

	return nil
}

// removeContainers force-removes the container named id (created before
// ownership labels existed) and every container labelled as id's.
func (d *DockerEngine) removeContainers(ctx context.Context, id string) error {
	opts := client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}
	if _, err := d.client.ContainerRemove(ctx, id, opts); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("container teardown failed: %w", err)
	}
	owned, err := d.client.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: make(client.Filters).Add("label", LabelEnv+"="+id)})
	if err != nil {
		return fmt.Errorf("list containers of %s: %w", id, err)
	}
	for _, c := range owned.Items {
		if _, err := d.client.ContainerRemove(ctx, c.ID, opts); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("container teardown failed: %w", err)
		}
	}
	return nil
}

// removeVolumes removes the named volumes labelled as id's.
func (d *DockerEngine) removeVolumes(ctx context.Context, id string) error {
	owned, err := d.client.VolumeList(ctx, client.VolumeListOptions{Filters: make(client.Filters).Add("label", LabelEnv+"="+id)})
	if err != nil {
		return fmt.Errorf("list volumes of %s: %w", id, err)
	}
	for _, v := range owned.Items {
		if _, err := d.client.VolumeRemove(ctx, v.Name, client.VolumeRemoveOptions{}); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("volume teardown failed: %w", err)
		}
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

// Observe reports, per environment, the containers (primary and sidecars),
// networks and named volumes previewd owns on the host: by ownership label,
// or by name for resources created before labels existed (container <env-id>,
// network <env-id>-net).
func (d *DockerEngine) Observe(ctx context.Context) (map[string]EngineState, error) {
	containers, err := d.client.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	networks, err := d.client.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	volumes, err := d.client.VolumeList(ctx, client.VolumeListOptions{Filters: make(client.Filters).Add("label", LabelEnv)})
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	return observe(containers.Items, networks.Items, volumes.Items), nil
}

// observe groups owned containers, networks and volumes by environment. A
// volume alone makes an environment (a crash between its creation and the
// first container): the sweep then destroys it.
func observe(containers []container.Summary, networks []network.Summary, volumes []volume.Volume) map[string]EngineState {
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
		st.Containers++
		if name == env { // the primary: sidecars are named <env>-<service>
			st.Running = st.Running || c.State == container.StateRunning
			if job, err := strconv.ParseInt(c.Labels[LabelJob], 10, 64); err == nil && job > 0 {
				st.JobID = job
			}
		}
		states[env] = st
	}
	for _, v := range volumes {
		env := ownerOf(v.Labels, "")
		if env == "" {
			continue
		}
		st := states[env]
		st.Volumes++
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

// PruneImages removes, one by one and never forced, every image
// prunableImages selects: built by previewd for an environment not in keep.
// An image gone meanwhile is skipped, and so is one a container still uses
// (conflict): the container is the environment's, which Observe reports
// and the sweep or a teardown removes with its image. reclaimed sums the
// sizes of the images removed (layers shared with a kept image included).
func (d *DockerEngine) PruneImages(ctx context.Context, keep []string) (int64, error) {
	res, err := d.client.ImageList(ctx, client.ImageListOptions{Filters: make(client.Filters).Add("label", LabelEnv)})
	if err != nil {
		return 0, fmt.Errorf("prune images: list: %w", err)
	}
	var reclaimed int64
	var errs []error
	for _, img := range prunableImages(res.Items, keep) {
		_, err := d.client.ImageRemove(ctx, img.ID, client.ImageRemoveOptions{PruneChildren: true})
		switch {
		case err == nil:
			reclaimed += max(img.Size, 0)
		case errdefs.IsNotFound(err) || errdefs.IsConflict(err):
		default:
			errs = append(errs, fmt.Errorf("prune image %s of %s: %w", img.ID, img.Labels[LabelEnv], err))
		}
	}
	return reclaimed, errors.Join(errs...)
}

// prunableImages selects the images previewd built (BuildSpec labels: a
// valid environment ID and a positive job ID; at most the tag
// <env>:latest, so an operator's image is never selected for carrying the
// labels) whose environment is not in keep.
func prunableImages(images []image.Summary, keep []string) []image.Summary {
	var out []image.Summary
	for _, img := range images {
		env := img.Labels[LabelEnv]
		job, err := strconv.ParseInt(img.Labels[LabelJob], 10, 64)
		if !envid.Valid(env) || err != nil || job <= 0 || slices.Contains(keep, env) {
			continue
		}
		ownTag := true
		for _, tag := range img.RepoTags {
			ownTag = ownTag && (tag == env+":latest" || tag == "<none>:<none>")
		}
		if ownTag {
			out = append(out, img)
		}
	}
	return out
}

// PruneBuildCache removes all of the daemon's unused build cache.
func (d *DockerEngine) PruneBuildCache(ctx context.Context) (int64, error) {
	res, err := d.client.BuildCachePrune(ctx, client.BuildCachePruneOptions{All: true})
	if err != nil {
		return 0, fmt.Errorf("prune build cache: %w", err)
	}
	return int64(min(res.Report.SpaceReclaimed, math.MaxInt64)), nil // #nosec G115 -- bounded by MaxInt64
}

// FreeDisk measures the file system of the data root: PREVIEWD_DOCKER_DATA_ROOT,
// or the DockerRootDir the daemon reports, which must be a clean absolute
// path. Any failure is an error: the floor is never assumed met.
func (d *DockerEngine) FreeDisk(ctx context.Context) (int64, error) {
	root := d.dataRoot
	if root == "" {
		res, err := d.client.Info(ctx, client.InfoOptions{})
		if err != nil {
			return 0, fmt.Errorf("free disk: docker info: %w", err)
		}
		root = res.Info.DockerRootDir
		if !filepath.IsAbs(root) || root != filepath.Clean(root) {
			return 0, fmt.Errorf("free disk: the daemon's data root %q is not a clean absolute path", textutil.Truncate(root, 256))
		}
	}
	if d.statDisk == nil {
		return 0, errors.New("free disk: no free-disk probe")
	}
	free, err := d.statDisk(root)
	if err != nil {
		return 0, fmt.Errorf("free disk of the docker data root (set PREVIEWD_DOCKER_DATA_ROOT to a path previewd can statfs): %w", err)
	}
	return free, nil
}

// Close gracefully terminates the SDK connection.
func (d *DockerEngine) Close() error {
	return d.client.Close()
}
