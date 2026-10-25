package hardening

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrEgressFilter is a systemd IP address filter that is absent, partial,
// defeated by an allow-list, or not loaded.
var ErrEgressFilter = errors.New("egress filter check failed")

// minAllowBits is the shortest prefix an IPAddressAllow entry may have.
// Loopback (127.0.0.0/8) and the proxy network are narrower; an entry
// shorter than a /8 re-opens most of the address space the deny closed.
const minAllowBits = 8

// egressProps are the properties CheckEgressFilter reads.
var egressProps = []string{"IPAddressDeny", "IPAddressAllow", "NeedDaemonReload"}

// CheckUnitEgress reads the IP filter of unit through show and checks it
// (CheckEgressFilter). It is how the doctor proves that dockerd, which
// contacts a registry from the host network namespace at every build
// (D-V1-2), cannot reach beyond loopback, the proxy network and the
// site's mirror.
func CheckUnitEgress(ctx context.Context, show ShowFunc, unit string) error {
	out, err := show(ctx, unit, egressProps...)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrEgressFilter, unit, err)
	}
	if err := CheckEgressFilter(out); err != nil {
		return fmt.Errorf("%s: %w", unit, err)
	}
	return nil
}

// CheckEgressFilter checks `systemctl show` output: IPAddressDeny covers
// all of IPv4 and IPv6 (0.0.0.0/0 and ::/0, or "any"), no IPAddressAllow
// entry re-opens a /0 or anything shorter than a /8, and the unit's files
// are loaded (NeedDaemonReload is "no" when reported): a drop-in on disk
// that systemd has not read filters nothing.
func CheckEgressFilter(out []byte) error {
	props, err := parseShow(out)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEgressFilter, err)
	}
	deny, ok := props["IPAddressDeny"]
	if !ok {
		return fmt.Errorf("%w: IPAddressDeny is not reported", ErrEgressFilter)
	}
	var deny4, deny6 bool
	for _, tok := range strings.Fields(deny) {
		if tok == "any" {
			deny4, deny6 = true, true
			continue
		}
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return fmt.Errorf("%w: IPAddressDeny entry %q: %w", ErrEgressFilter, tok, err)
		}
		if p.Bits() == 0 {
			deny4 = deny4 || p.Addr().Is4()
			deny6 = deny6 || p.Addr().Is6()
		}
	}
	if !deny4 || !deny6 {
		return fmt.Errorf("%w: IPAddressDeny=%q does not deny all of IPv4 (0.0.0.0/0) and IPv6 (::/0)", ErrEgressFilter, deny)
	}
	for _, tok := range strings.Fields(props["IPAddressAllow"]) {
		if tok == "any" {
			return fmt.Errorf("%w: IPAddressAllow=any defeats the filter", ErrEgressFilter)
		}
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return fmt.Errorf("%w: IPAddressAllow entry %q: %w", ErrEgressFilter, tok, err)
		}
		if p.Bits() < minAllowBits {
			return fmt.Errorf("%w: IPAddressAllow entry %s is wider than a /%d", ErrEgressFilter, p, minAllowBits)
		}
	}
	switch props["NeedDaemonReload"] {
	case "", "no":
	case "yes":
		return fmt.Errorf("%w: unit files changed on disk, not loaded: systemctl daemon-reload", ErrEgressFilter)
	default:
		return fmt.Errorf("%w: NeedDaemonReload=%q", ErrEgressFilter, props["NeedDaemonReload"])
	}
	return nil
}
