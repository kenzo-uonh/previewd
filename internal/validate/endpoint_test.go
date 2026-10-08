package validate

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestGHESURL(t *testing.T) {
	for in, want := range map[string]string{"https://ghes.corp": "https://ghes.corp", "https://ghes.corp/": "https://ghes.corp",
		"https://10.0.0.1:8443": "https://10.0.0.1:8443", "https://[fd00::1]:443": "https://[fd00::1]:443"} {
		if got, err := GHESURL(in); err != nil || got != want {
			t.Errorf("GHESURL(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "http://ghes.corp", "https://", "https://u:p@ghes.corp", "https://u@ghes.corp",
		"https://ghes.corp/api/v3", "https://ghes.corp?x=1", "https://ghes.corp?", "https://ghes.corp#f", "ghes.corp",
		"https:ghes.corp", "file:///etc/passwd", "HTTPS://ghes.corp/x", "https://:443"} {
		if got, err := GHESURL(bad); err == nil {
			t.Errorf("GHESURL(%q) = %q, want an error", bad, got)
		}
	}
}

func TestCredentialName(t *testing.T) {
	for _, ok := range []string{"github-app-key", "tls.key", "A_1"} {
		if err := CredentialName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "/etc/key", "../key", "key ", "kéy", strings.Repeat("k", 65)} {
		if err := CredentialName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCIDRs(t *testing.T) {
	got, err := CIDRs("10.20.0.0/16,fd00::/8,192.0.2.7/32")
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("192.0.2.7/32")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("CIDRs = %v, %v", got, err)
	}
	if got, err := CIDRs(""); err != nil || got != nil {
		t.Fatalf("empty = %v, %v", got, err)
	}
	for _, bad := range []string{",", "10.0.0.0/8,", "10.0.0.1", "10.0.0.1/8", " 10.0.0.0/8", "10.0.0.0/33", "fd00::1/8", "any"} {
		if got, err := CIDRs(bad); err == nil {
			t.Errorf("CIDRs(%q) = %v, want an error", bad, got)
		}
	}
}
