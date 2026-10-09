package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/netip"
	"time"

	"github.com/kenzo-uonh/previewd/internal/hardening"
)

// Exit codes of `previewd build-probe`. The daemon reads them from the
// build's stream error ("exit code: N") when the startup probe fails.
const (
	exitProbeInterface = 3 // an interface other than loopback
	exitProbeRoute     = 4 // a route
	exitProbeReachable = 5 // the probe address answered, refused, or timed out
	exitProbeCancelled = 6 // stopped before the host could observe it
)

const (
	maxProbeHold    = 30 * time.Second
	maxProbeTimeout = 30 * time.Second
)

const buildProbeUsage = `usage:
  previewd build-probe -addr IP:PORT [-hold 3s] [-timeout 3s]
      Run inside a BuildKit RUN step by the daemon's startup probe. Exit 0
      only if no interface but loopback exists, no route exists, and a TCP
      connection to -addr fails as unreachable; then stay alive for -hold so
      the host can see the step in the build cgroup. Exit 3 (interface),
      4 (route) or 5 (the address answered, refused or timed out).
`

// probeFunc checks the network namespace (hardening.ProbeNoNetwork).
type probeFunc func(ctx context.Context, addr netip.AddrPort, timeout time.Duration) error

// runBuildProbe is `previewd build-probe`.
func runBuildProbe(ctx context.Context, args []string, stdout, stderr io.Writer, probe probeFunc) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	fs := flag.NewFlagSet("build-probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addrFlag := fs.String("addr", "", "")
	hold := fs.Duration("hold", 3*time.Second, "")
	timeout := fs.Duration("timeout", 3*time.Second, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		diag.printf("previewd build-probe: invalid arguments\n%s", buildProbeUsage)
		return exitUsage
	}
	addr, err := netip.ParseAddrPort(*addrFlag)
	if err != nil || addr.Port() == 0 || *hold < 0 || *hold > maxProbeHold || *timeout <= 0 || *timeout > maxProbeTimeout {
		diag.printf("previewd build-probe: -addr must be IP:PORT, -hold within 0..%s, -timeout within 1ns..%s\n%s", maxProbeHold, maxProbeTimeout, buildProbeUsage)
		return exitUsage
	}

	if err := probe(ctx, addr, *timeout); err != nil {
		diag.printf("previewd build-probe: %v\n", err)
		switch {
		case errors.Is(err, hardening.ErrNetworkInterface):
			return exitProbeInterface
		case errors.Is(err, hardening.ErrNetworkRoute):
			return exitProbeRoute
		default:
			return exitProbeReachable
		}
	}
	out.printf("previewd build-probe: no interface but loopback, no route, %s unreachable\n", addr)
	select {
	case <-ctx.Done():
		return exitProbeCancelled
	case <-time.After(*hold):
	}
	return exitOK
}
