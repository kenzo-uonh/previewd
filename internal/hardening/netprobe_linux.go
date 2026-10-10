package hardening

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ProbeNoNetwork runs the build probe's checks in the current network
// namespace: CheckInterfaces, CheckRoutes on /proc/net, then a TCP dial to
// addr that must fail as unreachable (ClassifyProbeDial).
func ProbeNoNetwork(ctx context.Context, addr netip.AddrPort, timeout time.Duration) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("%w: list interfaces: %w", ErrNetworkInterface, err)
	}
	if err := CheckInterfaces(ifaces); err != nil {
		return err
	}
	route4, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNetworkRoute, err)
	}
	route6, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrNetworkRoute, err)
	}
	if err := CheckRoutes(route4, route6); err != nil {
		return err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err == nil {
		_ = conn.Close()
	}
	return ClassifyProbeDial(addr, err)
}

// ClassifyProbeDial passes only a dial that failed with ENETUNREACH or
// EHOSTUNREACH. A connection, a refusal (a reply), a timeout (a path may
// drop silently) or any other error fails.
func ClassifyProbeDial(addr netip.AddrPort, err error) error {
	switch {
	case err == nil:
		return fmt.Errorf("%w: connected to %s", ErrNetworkReachable, addr)
	case errors.Is(err, unix.ENETUNREACH), errors.Is(err, unix.EHOSTUNREACH):
		return nil
	default:
		return fmt.Errorf("%w: dial %s: %w", ErrNetworkReachable, addr, err)
	}
}
