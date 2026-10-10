package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/kenzo-uonh/previewd/internal/hardening"
)

func probeReturning(err error) probeFunc {
	return func(context.Context, netip.AddrPort, time.Duration) error { return err }
}

// Each failed check has its own exit code; only a clean probe exits 0.
func TestBuildProbeExitCodes(t *testing.T) {
	for want, err := range map[int]error{
		exitOK:             nil,
		exitProbeInterface: fmt.Errorf("%w: \"eth0\"", hardening.ErrNetworkInterface),
		exitProbeRoute:     fmt.Errorf("%w: IPv4 route on \"eth0\"", hardening.ErrNetworkRoute),
		exitProbeReachable: fmt.Errorf("%w: connected", hardening.ErrNetworkReachable),
	} {
		var stdout, stderr bytes.Buffer
		got := runBuildProbe(context.Background(), []string{"-addr", "172.17.0.1:9", "-hold", "0s"}, &stdout, &stderr, probeReturning(err))
		if got != want {
			t.Errorf("probe error %v: exit %d, want %d (stderr %q)", err, got, want, stderr.String())
		}
	}
	// An error of no known kind fails as reachable, never as success.
	var stdout, stderr bytes.Buffer
	if got := runBuildProbe(context.Background(), []string{"-addr", "172.17.0.1:9"}, &stdout, &stderr, probeReturning(errors.New("boom"))); got != exitProbeReachable {
		t.Fatalf("unknown error: exit %d", got)
	}
}

func TestBuildProbePassesItsArguments(t *testing.T) {
	var gotAddr netip.AddrPort
	var gotTimeout time.Duration
	probe := func(_ context.Context, a netip.AddrPort, d time.Duration) error {
		gotAddr, gotTimeout = a, d
		return nil
	}
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := runBuildProbe(context.Background(), []string{"-addr", "[fd00::1]:9", "-hold", "50ms", "-timeout", "2s"}, &stdout, &stderr, probe)
	if code != exitOK || gotAddr.String() != "[fd00::1]:9" || gotTimeout != 2*time.Second {
		t.Fatalf("exit %d, addr %v, timeout %v", code, gotAddr, gotTimeout)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("the probe did not hold")
	}
}

func TestBuildProbeUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-addr", "gateway:9"},
		{"-addr", "172.17.0.1"},
		{"-addr", "172.17.0.1:0"},
		{"-addr", "172.17.0.1:9", "-hold", "31s"},
		{"-addr", "172.17.0.1:9", "-hold", "-1s"},
		{"-addr", "172.17.0.1:9", "-timeout", "0s"},
		{"-addr", "172.17.0.1:9", "extra"},
		{"-nope"},
	} {
		var stdout, stderr bytes.Buffer
		ran := false
		probe := func(context.Context, netip.AddrPort, time.Duration) error { ran = true; return nil }
		if got := runBuildProbe(context.Background(), args, &stdout, &stderr, probe); got != exitUsage || ran {
			t.Errorf("%q: exit %d, probe ran %v", args, got, ran)
		}
	}
}

// Cancelled during the hold: the host may not have seen the step.
func TestBuildProbeCancelledHold(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if got := runBuildProbe(ctx, []string{"-addr", "172.17.0.1:9", "-hold", "10s"}, &stdout, &stderr, probeReturning(nil)); got != exitProbeCancelled {
		t.Fatalf("exit %d", got)
	}
}
