package hardening

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var probeAddr = netip.MustParseAddrPort("172.17.0.1:9")

// Only "unreachable" passes: a connection, a refusal (a reply), a timeout
// (a path that drops) and anything unknown fail.
func TestClassifyProbeDial(t *testing.T) {
	opErr := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)}
	}
	for _, err := range []error{opErr(unix.ENETUNREACH), opErr(unix.EHOSTUNREACH)} {
		if got := ClassifyProbeDial(probeAddr, err); got != nil {
			t.Errorf("%v refused: %v", err, got)
		}
	}
	for name, err := range map[string]error{
		"connected":  nil,
		"refused":    opErr(unix.ECONNREFUSED),
		"timeout":    &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded},
		"permission": opErr(unix.EPERM),
		"other":      errors.New("boom"),
	} {
		if got := ClassifyProbeDial(probeAddr, err); !errors.Is(got, ErrNetworkReachable) {
			t.Errorf("%s accepted: %v", name, got)
		}
	}
}

// Real dials: an accepting and a refusing loopback port both fail.
func TestClassifyProbeDialRealReplies(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := netip.MustParseAddrPort(ln.Addr().String())
	conn, dialErr := net.DialTimeout("tcp", open.String(), time.Second)
	if dialErr == nil {
		_ = conn.Close()
	}
	if err := ClassifyProbeDial(open, dialErr); !errors.Is(err, ErrNetworkReachable) {
		t.Fatalf("accepted connection: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	_, dialErr = net.DialTimeout("tcp", open.String(), time.Second)
	if err := ClassifyProbeDial(open, dialErr); !errors.Is(err, ErrNetworkReachable) {
		t.Fatalf("refused connection accepted: %v (%v)", err, dialErr)
	}
}

// The test host has a network: the probe must say so.
func TestProbeNoNetworkFailsOnAHostWithNetwork(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if CheckInterfaces(ifaces) == nil {
		t.Skip("this test host has loopback only")
	}
	if err := ProbeNoNetwork(context.Background(), probeAddr, time.Second); !errors.Is(err, ErrNetworkInterface) {
		t.Fatalf("ProbeNoNetwork on a host with network = %v", err)
	}
}
