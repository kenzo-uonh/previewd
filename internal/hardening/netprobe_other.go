//go:build !linux

package hardening

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ProbeNoNetwork fails closed: the build probe runs in a Linux BuildKit step.
func ProbeNoNetwork(context.Context, netip.AddrPort, time.Duration) error {
	return errors.New("the build probe requires Linux")
}

// ClassifyProbeDial fails closed outside Linux.
func ClassifyProbeDial(netip.AddrPort, error) error {
	return errors.New("the build probe requires Linux")
}
