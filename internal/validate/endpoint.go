package validate

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// GHESURL validates PREVIEWD_GHES_URL: https, a host, no user info, no
// path, query or fragment. It returns the URL without a trailing slash.
func GHESURL(s string) (string, error) { return forgeURL("GHES", s) }

// forgeURL validates the base URL of the forge called name.
func forgeURL(name, s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("%s URL %s must be https://host[:port] with no user info, path, query or fragment", name, Quote(s))
	}
	return "https://" + u.Host, nil
}

// CredentialName validates a systemd credential name: 1 to 64 of
// [A-Za-z0-9._-], not "." or "..". It is a name under
// $CREDENTIALS_DIRECTORY, never a path.
func CredentialName(s string) error {
	if s == "" || len(s) > 64 || s == "." || s == ".." {
		return fmt.Errorf("invalid credential name %s", Quote(s))
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("invalid credential name %s", Quote(s))
		}
	}
	return nil
}

// CIDRs parses PREVIEWD_WEBHOOK_ALLOWED_CIDRS: comma-separated prefixes in
// canonical form (no host bits). An empty value is no filter; an empty
// entry, a bare address or a prefix with host bits set is an error, so a
// typo never widens the filter.
func CIDRs(s string) ([]netip.Prefix, error) {
	if s == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for i, entry := range strings.Split(s, ",") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("CIDR entry %d %s: want a prefix such as 10.0.0.0/8", i+1, Quote(entry))
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("CIDR entry %d %s has host bits set: did you mean %s?", i+1, Quote(entry), p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}
