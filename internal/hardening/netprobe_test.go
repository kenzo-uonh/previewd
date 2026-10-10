package hardening

import (
	"errors"
	"net"
	"testing"
)

const route4Header = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

// The IPv6 table of a BuildKit RUN under networkmode=none, recorded on
// Docker 29.8.2: loopback and multicast routes of lo only.
const route6LoOnly = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo
`

func TestCheckInterfaces(t *testing.T) {
	lo := net.Interface{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback}
	if err := CheckInterfaces([]net.Interface{lo}); err != nil {
		t.Fatalf("loopback only: %v", err)
	}
	if err := CheckInterfaces(nil); err != nil {
		t.Fatalf("no interface: %v", err)
	}
	for _, ifc := range []net.Interface{
		{Index: 2, Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast},
		{Index: 3, Name: "eth1"}, // down still counts: it can be brought up
		{Index: 4, Name: "lo2", Flags: net.FlagUp},
	} {
		if err := CheckInterfaces([]net.Interface{lo, ifc}); !errors.Is(err, ErrNetworkInterface) {
			t.Errorf("%s accepted: %v", ifc.Name, err)
		}
	}
}

func TestCheckRoutes(t *testing.T) {
	if err := CheckRoutes([]byte(route4Header), []byte(route6LoOnly)); err != nil {
		t.Fatalf("isolated namespace refused: %v", err)
	}
	if err := CheckRoutes([]byte(route4Header), nil); err != nil {
		t.Fatalf("IPv6 off refused: %v", err)
	}
	for name, tc := range map[string][2]string{
		"IPv4 default route": {route4Header + "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n", route6LoOnly},
		"IPv4 route on lo":   {route4Header + "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n", route6LoOnly},
		"IPv6 route on eth0": {route4Header, route6LoOnly + "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"},
		"IPv6 malformed":     {route4Header, "00 lo\n"},
		"IPv4 no header":     {"", route6LoOnly},
		"IPv4 wrong header":  {"garbage\n", route6LoOnly},
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckRoutes([]byte(tc[0]), []byte(tc[1])); !errors.Is(err, ErrNetworkRoute) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}
