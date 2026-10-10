package hardening

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

// The build probe (V1 F2, task E2b) runs inside a BuildKit RUN step and
// proves the step has no network: no interface but loopback, no route, and
// no reply from a host address. Each failure has its own error, so the
// probe's exit code says which control failed.
var (
	// ErrNetworkInterface is an interface other than loopback.
	ErrNetworkInterface = errors.New("network interface other than loopback")
	// ErrNetworkRoute is a route: any IPv4 route, an IPv6 route off loopback.
	ErrNetworkRoute = errors.New("network route present")
	// ErrNetworkReachable is a reply from the probe address, or a dial that
	// did not fail as unreachable: a refusal is a reply, a timeout may hide
	// a path that drops.
	ErrNetworkReachable = errors.New("probe address not unreachable")
)

// CheckInterfaces fails unless every interface is a loopback one.
func CheckInterfaces(ifaces []net.Interface) error {
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback == 0 {
			return fmt.Errorf("%w: %q", ErrNetworkInterface, ifc.Name)
		}
	}
	return nil
}

// CheckRoutes reads /proc/net/route (route4) and /proc/net/ipv6_route
// (route6, nil when IPv6 is off). The IPv4 main table must be empty: it
// lists no loopback route. IPv6 entries are allowed on lo only: the kernel
// lists the loopback and multicast routes of lo there in an isolated
// namespace.
func CheckRoutes(route4, route6 []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(route4))
	if !sc.Scan() || !strings.HasPrefix(sc.Text(), "Iface") {
		return fmt.Errorf("%w: unreadable IPv4 route table", ErrNetworkRoute)
	}
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 0 {
			return fmt.Errorf("%w: IPv4 route on %q", ErrNetworkRoute, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: read IPv4 route table: %w", ErrNetworkRoute, err)
	}
	sc = bufio.NewScanner(bytes.NewReader(route6))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 10 {
			return fmt.Errorf("%w: unreadable IPv6 route %q", ErrNetworkRoute, sc.Text())
		}
		if dev := fields[9]; dev != "lo" {
			return fmt.Errorf("%w: IPv6 route on %q", ErrNetworkRoute, dev)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: read IPv6 route table: %w", ErrNetworkRoute, err)
	}
	return nil
}
