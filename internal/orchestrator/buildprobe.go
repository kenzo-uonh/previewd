package orchestrator

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// The startup build probe (V1 F2, task E2b, D-V1-4). Before the startup
// sweep, while no worker runs, the daemon builds an image whose only RUN step
// is the previewd binary itself (`previewd build-probe`), with the exact
// request PR builds get. The step proves from inside that it has no network;
// the host proves the step ran in the bounded cgroup subtree and left
// nothing behind. Any failure refuses the start.

// ErrBuildIsolation is a startup build probe that did not verify.
var ErrBuildIsolation = errors.New("build isolation not verified")

// BuildProber runs the probe build (DockerEngine.BuildProbe).
type BuildProber interface {
	BuildProbe(ctx context.Context, addr netip.AddrPort) error
}

// BuildCgroup is the host view of PREVIEWD_BUILDKIT_CGROUP
// (hardening.BuildCgroup).
type BuildCgroup interface {
	CheckLimits() error
	Procs() ([]int, error)
}

// BuildIsolation configures VerifyBuildIsolation.
type BuildIsolation struct {
	Prober    BuildProber
	ProbeAddr netip.AddrPort
	// Cgroup is the bounded subtree. Unbounded is the
	// PREVIEWD_ALLOW_UNBOUNDED_BUILDS opt-in: no subtree, the network probe
	// only. Exactly one of them is set.
	Cgroup    BuildCgroup
	Unbounded bool
	// Poll is the interval of the placement check (default 50 ms); Drain how
	// long the probe's processes may take to leave the subtree (default 10 s).
	Poll, Drain time.Duration
}

const (
	defaultProbePoll  = 50 * time.Millisecond
	defaultProbeDrain = 10 * time.Second
)

// VerifyBuildIsolation runs the startup build probe:
//  1. the subtree's limits are finite and its swap is 0 (CheckLimits);
//  2. the subtree is idle: no build runs at this point, so a process there
//     means it is not dedicated to builds;
//  3. the probe build succeeds: its RUN found no interface but loopback, no
//     route, and no reply from ProbeAddr (exit code otherwise, in the stream);
//  4. a process appeared in the subtree while the probe ran;
//  5. none is left within Drain after it.
//
// With Unbounded, only step 3 runs.
func VerifyBuildIsolation(ctx context.Context, v BuildIsolation) error {
	if v.Prober == nil || !v.ProbeAddr.IsValid() || v.ProbeAddr.Port() == 0 {
		return fmt.Errorf("%w: a prober and a probe address are required", ErrBuildIsolation)
	}
	if v.Unbounded == (v.Cgroup != nil) {
		return fmt.Errorf("%w: set either the build cgroup or the unbounded opt-in, not both or neither", ErrBuildIsolation)
	}
	if v.Poll <= 0 {
		v.Poll = defaultProbePoll
	}
	if v.Drain <= 0 {
		v.Drain = defaultProbeDrain
	}
	if v.Unbounded {
		if err := v.Prober.BuildProbe(ctx, v.ProbeAddr); err != nil {
			return fmt.Errorf("%w: probe build: %w", ErrBuildIsolation, err)
		}
		return nil
	}

	if err := v.Cgroup.CheckLimits(); err != nil {
		return fmt.Errorf("%w: %w", ErrBuildIsolation, err)
	}
	before, err := v.Cgroup.Procs()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBuildIsolation, err)
	}
	if len(before) > 0 {
		return fmt.Errorf("%w: the build cgroup holds %d process(es) before the probe: it is not dedicated to builds", ErrBuildIsolation, len(before))
	}

	done := make(chan error, 1)
	go func() { done <- v.Prober.BuildProbe(ctx, v.ProbeAddr) }()
	ticker := time.NewTicker(v.Poll)
	defer ticker.Stop()
	var (
		seen     bool
		procErr  error
		buildErr error
	)
wait:
	for {
		select {
		case buildErr = <-done:
			break wait
		case <-ticker.C:
			pids, err := v.Cgroup.Procs()
			if err != nil {
				procErr = firstErr(procErr, err)
				continue
			}
			seen = seen || len(pids) > 0
		}
	}
	if buildErr != nil {
		return fmt.Errorf("%w: probe build: %w", ErrBuildIsolation, buildErr)
	}
	if procErr != nil {
		return fmt.Errorf("%w: during the probe: %w", ErrBuildIsolation, procErr)
	}
	if !seen {
		return fmt.Errorf("%w: no process appeared in the build cgroup during the probe: the engine runs builds outside the bounded subtree", ErrBuildIsolation)
	}

	deadline := time.Now().Add(v.Drain)
	for {
		pids, err := v.Cgroup.Procs()
		if err != nil {
			return fmt.Errorf("%w: after the probe: %w", ErrBuildIsolation, err)
		}
		if len(pids) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %d process(es) left in the build cgroup %s after the probe", ErrBuildIsolation, len(pids), v.Drain)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrBuildIsolation, ctx.Err())
		case <-ticker.C:
		}
	}
}

// firstErr keeps the first error.
func firstErr(first, next error) error {
	if first != nil {
		return first
	}
	return next
}

const (
	// probeTag is the probe image, removed after the probe.
	probeTag = "previewd-build-probe:latest"
	// LabelProbe marks the probe image.
	LabelProbe = "previewd.probe"
	// probeHold keeps the probe's RUN alive long enough to be seen in the
	// build cgroup; probeDialTimeout bounds its TCP attempt.
	probeHold        = 3 * time.Second
	probeDialTimeout = 3 * time.Second
)

// probeDockerfile is the probe build: no base image, nothing to pull, the
// static previewd binary as the only file, run as the only RUN step.
func probeDockerfile(addr netip.AddrPort) []byte {
	return fmt.Appendf(nil, "FROM scratch\nCOPY previewd /previewd\nRUN [\"/previewd\", \"build-probe\", \"-addr\", %s, \"-hold\", %s, \"-timeout\", %s]\n",
		strconv.Quote(addr.String()), strconv.Quote(probeHold.String()), strconv.Quote(probeDialTimeout.String()))
}

// BuildProbe builds probeDockerfile with lockedBuildOptions, the request PR
// builds send, the running previewd binary as the context's only file, and
// removes the image. The build fails, with the probe's exit code in the
// stream error, unless the RUN step found no network (`previewd build-probe`).
func (d *DockerEngine) BuildProbe(ctx context.Context, addr netip.AddrPort) (err error) {
	dockerfile := probeDockerfile(addr)
	if err := Preflight(dockerfile, nil); err != nil {
		return fmt.Errorf("probe Dockerfile: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate the previewd binary: %w", err)
	}
	bin, err := os.Open(exe) // #nosec G304 -- the running executable
	if err != nil {
		return fmt.Errorf("open the previewd binary: %w", err)
	}
	defer func() { _ = bin.Close() }()
	st, err := bin.Stat()
	if err != nil {
		return fmt.Errorf("stat the previewd binary: %w", err)
	}

	pr, pw := io.Pipe()
	written := make(chan error, 1)
	go func() {
		err := writeProbeContext(pw, dockerfile, bin, st.Size())
		_ = pw.CloseWithError(err)
		written <- err
	}()
	defer func() {
		_ = pr.Close()
		if wErr := <-written; wErr != nil && err == nil {
			err = fmt.Errorf("probe context: %w", wErr)
		}
		cctx, cancel := cleanupContext(ctx)
		defer cancel()
		if _, rmErr := d.client.ImageRemove(cctx, probeTag, client.ImageRemoveOptions{Force: true}); rmErr != nil && !errdefs.IsNotFound(rmErr) {
			err = errors.Join(err, fmt.Errorf("remove the probe image: %w", rmErr))
		}
	}()

	res, err := d.client.ImageBuild(ctx, pr, lockedBuildOptions(probeTag, map[string]string{LabelProbe: "1"}))
	if err != nil {
		return fmt.Errorf("probe build: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if _, err := readBuildStream(res.Body); err != nil {
		return fmt.Errorf("probe build: %w", err)
	}
	return nil
}

// writeProbeContext writes the probe's tar: the Dockerfile and the binary.
func writeProbeContext(w io.Writer, dockerfile []byte, bin io.Reader, size int64) error {
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: dockerfileName, Mode: 0o644, Size: int64(len(dockerfile)), Typeflag: tar.TypeReg}); err != nil {
		return fmt.Errorf("write probe Dockerfile: %w", err)
	}
	if _, err := tw.Write(dockerfile); err != nil {
		return fmt.Errorf("write probe Dockerfile: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "previewd", Mode: 0o755, Size: size, Typeflag: tar.TypeReg}); err != nil {
		return fmt.Errorf("write probe binary: %w", err)
	}
	if _, err := io.CopyN(tw, bin, size); err != nil {
		return fmt.Errorf("write probe binary: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("write probe context: %w", err)
	}
	return nil
}

// BridgeGateway is the IPv4 gateway of the engine's default bridge: the
// default probe address host (PREVIEWD_BUILD_PROBE_ADDR unset), a host
// address a RUN with any network would reach.
func (d *DockerEngine) BridgeGateway(ctx context.Context) (netip.Addr, error) {
	res, err := d.client.NetworkInspect(ctx, "bridge", client.NetworkInspectOptions{})
	if err != nil {
		return netip.Addr{}, fmt.Errorf("inspect the default bridge: %w", err)
	}
	for _, c := range res.Network.IPAM.Config {
		if c.Gateway.Is4() && !c.Gateway.IsUnspecified() {
			return c.Gateway, nil
		}
	}
	return netip.Addr{}, errors.New("the default bridge has no IPv4 gateway: set PREVIEWD_BUILD_PROBE_ADDR")
}
