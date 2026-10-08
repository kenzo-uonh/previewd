// Package validate holds the syntax validators for untrusted identifiers and
// the webhook ingestion checks (HMAC signature, payload schema). It is a
// leaf: it imports no internal package.
package validate

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	// GitHub: owner 1-39 of [A-Za-z0-9-]; repository 1-100 of [A-Za-z0-9._-].
	repoFullNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	commitSHAPattern    = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	// GitHub login: 1-39 of [A-Za-z0-9-], not starting with a hyphen; GHES
	// with external authentication may also normalize to underscores.
	loginPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

const (
	maxLabelLen     = 50
	maxTimestampLen = 35
	maxGitRefLen    = 255
	maxDNSNameLen   = 253
	maxQuotedLen    = 64
)

// quote renders untrusted input for an error message: escaped, and cut to
// maxQuotedLen bytes so a hostile value cannot flood a log line.
func quote(s string) string {
	if len(s) > maxQuotedLen {
		return fmt.Sprintf("%q...(%d bytes)", s[:maxQuotedLen], len(s))
	}
	return fmt.Sprintf("%q", s)
}

// RepoFullName validates "owner/repository".
func RepoFullName(s string) error {
	if !repoFullNamePattern.MatchString(s) {
		return fmt.Errorf("invalid repository name %s", quote(s))
	}
	if _, repo, _ := strings.Cut(s, "/"); repo == "." || repo == ".." {
		return fmt.Errorf("invalid repository name %s", quote(s))
	}
	return nil
}

// Login validates a GitHub login. A login names an account for logs and the
// audit trail only: identity is the numeric account ID.
func Login(s string) error {
	if !loginPattern.MatchString(s) {
		return fmt.Errorf("invalid login %s", quote(s))
	}
	return nil
}

// LabelName validates a GitHub label name: 1 to 50 bytes of valid UTF-8,
// no control character.
func LabelName(s string) error {
	if s == "" || len(s) > maxLabelLen || !utf8.ValidString(s) {
		return fmt.Errorf("invalid label %s", quote(s))
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("invalid label %s", quote(s))
		}
	}
	return nil
}

// Timestamp parses a GitHub timestamp (RFC 3339, as in updated_at and
// submitted_at) after the Unix epoch, in UTC.
func Timestamp(s string) (time.Time, error) {
	if len(s) > maxTimestampLen {
		return time.Time{}, fmt.Errorf("invalid timestamp %s", quote(s))
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Unix() <= 0 {
		return time.Time{}, fmt.Errorf("invalid timestamp %s", quote(s))
	}
	return t.UTC(), nil
}

// CommitSHA validates a full lowercase SHA-1 or SHA-256 object name.
func CommitSHA(s string) error {
	if !commitSHAPattern.MatchString(s) {
		return fmt.Errorf("invalid commit sha %s", quote(s))
	}
	return nil
}

// GitRef validates a branch name with the rules of git check-ref-format
// (one or more components, short form as GitHub sends it in head.ref).
func GitRef(s string) error {
	bad := func() error { return fmt.Errorf("invalid git ref %s", quote(s)) }

	if s == "" || len(s) > maxGitRefLen || s == "@" {
		return bad()
	}
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".") ||
		strings.Contains(s, "..") || strings.Contains(s, "//") || strings.Contains(s, "@{") {
		return bad()
	}
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte(" ~^:?*[\\", c) >= 0 {
			return bad()
		}
	}
	for comp := range strings.SplitSeq(s, "/") {
		if strings.HasPrefix(comp, ".") || strings.HasSuffix(comp, ".lock") {
			return bad()
		}
	}
	return nil
}

// DNSLabel validates an RFC 1123 label (lowercase).
func DNSLabel(s string) error {
	if !dnsLabelPattern.MatchString(s) {
		return fmt.Errorf("invalid DNS label %s", quote(s))
	}
	return nil
}

// DNSName validates a lowercase fully qualified name without trailing dot.
func DNSName(s string) error {
	if s == "" || len(s) > maxDNSNameLen {
		return fmt.Errorf("invalid DNS name %s", quote(s))
	}
	for label := range strings.SplitSeq(s, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return fmt.Errorf("invalid DNS name %s", quote(s))
		}
	}
	return nil
}
