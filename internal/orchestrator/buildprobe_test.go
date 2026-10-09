package orchestrator

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var testProbeAddr = netip.MustParseAddrPort("172.17.0.1:9")

// probeCgroup is a fake build cgroup; the fake prober moves processes in
// and out of it as a build would.
type probeCgroup struct {
	mu        sync.Mutex
	limitsErr error
	procs     []int
	procsErr  error
}

func (c *probeCgroup) CheckLimits() error { return c.limitsErr }

func (c *probeCgroup) Procs() ([]int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.procs...), c.procsErr
}

func (c *probeCgroup) set(pids []int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.procs, c.procsErr = pids, err
}

type proberFunc func(ctx context.Context, addr netip.AddrPort) error

func (f proberFunc) BuildProbe(ctx context.Context, addr netip.AddrPort) error { return f(ctx, addr) }

// runStep is a probe build whose RUN shows in the cgroup for a while.
func runStep(cg *probeCgroup, leave bool) proberFunc {
	return func(context.Context, netip.AddrPort) error {
		cg.set([]int{4242}, nil)
		time.Sleep(40 * time.Millisecond)
		if !leave {
			cg.set(nil, nil)
		}
		return nil
	}
}

func verify(cg *probeCgroup, p BuildProber) error {
	return VerifyBuildIsolation(context.Background(), BuildIsolation{
		Prober: p, ProbeAddr: testProbeAddr, Cgroup: cg, Poll: 5 * time.Millisecond, Drain: 100 * time.Millisecond,
	})
}

func TestVerifyBuildIsolationPasses(t *testing.T) {
	cg := &probeCgroup{}
	if err := verify(cg, runStep(cg, false)); err != nil {
		t.Fatalf("isolated, placed and drained probe refused: %v", err)
	}
	// Processes may take a moment to leave after the build answers.
	cg = &probeCgroup{}
	late := proberFunc(func(context.Context, netip.AddrPort) error {
		cg.set([]int{4242}, nil)
		time.Sleep(40 * time.Millisecond)
		time.AfterFunc(30*time.Millisecond, func() { cg.set(nil, nil) })
		return nil
	})
	if err := verify(cg, late); err != nil {
		t.Fatalf("late drain refused: %v", err)
	}
}

// Fail closed: every step refuses the start.
func TestVerifyBuildIsolationFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		cg     *probeCgroup
		prober func(*probeCgroup) proberFunc
		probed bool // whether the probe build must have run
	}{
		"limits":       {&probeCgroup{limitsErr: errors.New("memory.max is max")}, func(cg *probeCgroup) proberFunc { return runStep(cg, false) }, false},
		"busy subtree": {&probeCgroup{procs: []int{7}}, func(cg *probeCgroup) proberFunc { return runStep(cg, false) }, false},
		"unreadable":   {&probeCgroup{procsErr: errors.New("EACCES")}, func(cg *probeCgroup) proberFunc { return runStep(cg, false) }, false},
		"probe fails":  {&probeCgroup{}, func(*probeCgroup) proberFunc { return failingProbe }, true},
		"never placed": {&probeCgroup{}, func(*probeCgroup) proberFunc { return idleProbe }, true},
		"left behind":  {&probeCgroup{}, func(cg *probeCgroup) proberFunc { return runStep(cg, true) }, true},
		// The step is seen and leaves, but one read in between failed.
		"unreadable during": {&probeCgroup{}, func(cg *probeCgroup) proberFunc {
			return func(context.Context, netip.AddrPort) error {
				cg.set(nil, errors.New("EIO"))
				time.Sleep(30 * time.Millisecond)
				cg.set([]int{4242}, nil)
				time.Sleep(30 * time.Millisecond)
				cg.set(nil, nil)
				return nil
			}
		}, true},
		// Placed and drained, but the RUN step found a network.
		"probe fails after running": {&probeCgroup{}, func(cg *probeCgroup) proberFunc {
			return func(ctx context.Context, a netip.AddrPort) error {
				if err := runStep(cg, false)(ctx, a); err != nil {
					return err
				}
				return failingProbe(ctx, a)
			}
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			ran := false
			p := tc.prober(tc.cg)
			err := verify(tc.cg, proberFunc(func(ctx context.Context, a netip.AddrPort) error {
				ran = true
				return p(ctx, a)
			}))
			if !errors.Is(err, ErrBuildIsolation) {
				t.Fatalf("accepted: %v", err)
			}
			if ran != tc.probed {
				t.Fatalf("probe build ran = %v, want %v", ran, tc.probed)
			}
		})
	}
}

func failingProbe(context.Context, netip.AddrPort) error {
	return errors.New(`build failed: "process \"/previewd build-probe\" did not complete successfully: exit code: 3"`)
}

func idleProbe(context.Context, netip.AddrPort) error {
	time.Sleep(40 * time.Millisecond)
	return nil
}

// The opt-in skips the cgroup, never the network probe; a configuration
// with neither or both, or without a probe address, is refused.
func TestVerifyBuildIsolationConfiguration(t *testing.T) {
	ran := false
	ok := proberFunc(func(context.Context, netip.AddrPort) error { ran = true; return nil })
	if err := VerifyBuildIsolation(context.Background(), BuildIsolation{Prober: ok, ProbeAddr: testProbeAddr, Unbounded: true}); err != nil || !ran {
		t.Fatalf("unbounded = %v, probe ran %v", err, ran)
	}
	if err := VerifyBuildIsolation(context.Background(), BuildIsolation{Prober: proberFunc(failingProbe), ProbeAddr: testProbeAddr, Unbounded: true}); !errors.Is(err, ErrBuildIsolation) {
		t.Fatalf("unbounded with a failing probe: %v", err)
	}
	cg := &probeCgroup{}
	for name, v := range map[string]BuildIsolation{
		"neither":    {Prober: ok, ProbeAddr: testProbeAddr},
		"both":       {Prober: ok, ProbeAddr: testProbeAddr, Cgroup: cg, Unbounded: true},
		"no prober":  {ProbeAddr: testProbeAddr, Unbounded: true},
		"no address": {Prober: ok, Unbounded: true},
		"port 0":     {Prober: ok, ProbeAddr: netip.AddrPortFrom(testProbeAddr.Addr(), 0), Unbounded: true},
	} {
		if err := VerifyBuildIsolation(context.Background(), v); !errors.Is(err, ErrBuildIsolation) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// The probe build sends the request PR builds send, with the probe's tag
// and label; its context is the probe Dockerfile and the running binary;
// the image is removed, after a failure too.
func TestBuildProbeRequest(t *testing.T) {
	for _, stream := range []string{"buildkit-ok.jsonl", "buildkit-run-fails.jsonl"} {
		t.Run(stream, func(t *testing.T) {
			f := &fakeDaemon{stream: recordedStream(t, stream)}
			e := newFakeEngine(t, f)
			err := e.BuildProbe(context.Background(), testProbeAddr)
			if (err == nil) != (stream == "buildkit-ok.jsonl") {
				t.Fatalf("BuildProbe = %v", err)
			}
			if stream != "buildkit-ok.jsonl" && !errors.Is(err, ErrBuildFailed) {
				t.Fatalf("failing probe = %v, want ErrBuildFailed", err)
			}
			idx := f.builds()
			if len(idx) != 1 {
				t.Fatalf("%d build requests", len(idx))
			}
			assertLockedQuery(t, f.requests[idx[0]].URL.Query(), probeTag, `{"previewd.probe":"1"}`)
			files := tarFiles(t, f.bodies[idx[0]])
			if got := string(files[dockerfileName]); got != string(probeDockerfile(testProbeAddr)) {
				t.Fatalf("probe Dockerfile = %q", got)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(exe)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(files["previewd"], want) {
				t.Fatalf("probe binary of %d bytes, want the running executable (%d bytes)", len(files["previewd"]), len(want))
			}
			removed := false
			for _, r := range f.requests {
				removed = removed || (r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/images/"+probeTag))
			}
			if !removed {
				t.Fatal("probe image not removed")
			}
		})
	}
}

func tarFiles(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(body))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "previewd" && hdr.Mode != 0o755 {
			t.Fatalf("probe binary mode %o", hdr.Mode)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = b
	}
}

// The probe Dockerfile passes the preflight with no allowed base image: no
// image, no pull, one exec-form RUN without flags.
func TestProbeDockerfileNeedsNoImage(t *testing.T) {
	for _, a := range []string{"172.17.0.1:9", "[fd00::1]:9"} {
		if err := Preflight(probeDockerfile(netip.MustParseAddrPort(a)), nil); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

func TestBridgeGateway(t *testing.T) {
	e := newFakeEngine(t, &fakeDaemon{bridge: `{"Name":"bridge","IPAM":{"Config":[{"Subnet":"fd00::/64","Gateway":"fd00::1"},{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}`})
	if gw, err := e.BridgeGateway(context.Background()); err != nil || gw.String() != "172.17.0.1" {
		t.Fatalf("BridgeGateway = %v, %v", gw, err)
	}
	e = newFakeEngine(t, &fakeDaemon{bridge: `{"Name":"bridge","IPAM":{"Config":[]}}`})
	if gw, err := e.BridgeGateway(context.Background()); err == nil {
		t.Fatalf("no gateway accepted: %v", gw)
	}
}
