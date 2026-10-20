package validate

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// GitLab identifiers (V1.1 spec 3.1). GitLab spells a project by its
// namespace path, nested up to 20 groups deep, and by a numeric ID; the API
// is addressed by the ID only, so a path is never put in a URL.
const (
	maxGitLabNameLen   = 255
	maxGitLabDepth     = 22 // a group, 20 nested subgroups and the project
	gitLabTimestampMax = 35
)

// gitLabTimestampLayouts are the shapes GitLab writes a time in: webhook
// bodies ("2026-10-20 10:30:05 UTC", or with a numeric offset) and the REST
// API (RFC 3339).
var gitLabTimestampLayouts = []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700", time.RFC3339}

// gitLabName checks one path segment or a username: letters, digits, '_',
// '-' and '.', not starting with '-' or '.', not ending with '.', ".git" or
// ".atom" (GitLab's own rules, which keep a name from being read as a file
// or a URL suffix).
func gitLabName(s string) bool {
	if s == "" || len(s) > maxGitLabNameLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		alnum := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_'
		if !alnum && (i == 0 || (c != '-' && c != '.')) {
			return false
		}
	}
	return !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, ".git") && !strings.HasSuffix(s, ".atom")
}

// The longest project path and login the queue and the audit trail keep
// (store.maxRepoLen, store.maxLoginLen: GitHub's own limits). GitLab allows
// more; what cannot be kept is refused where it enters.
const (
	maxStoredRepoLen  = 140
	maxStoredLoginLen = 39
)

// GitLabProjectPath validates path_with_namespace: two to 22 segments, each
// a GitLab name, the whole at most 140 bytes.
func GitLabProjectPath(s string) error {
	segments := strings.Split(s, "/")
	if len(s) > maxStoredRepoLen || len(segments) < 2 || len(segments) > maxGitLabDepth {
		return fmt.Errorf("invalid GitLab project path %s", Quote(s))
	}
	for _, seg := range segments {
		if !gitLabName(seg) {
			return fmt.Errorf("invalid GitLab project path %s", Quote(s))
		}
	}
	return nil
}

// GitLabUsername validates a GitLab username. As with a GitHub login, it
// names an account for logs and the audit trail only: identity is the ID.
func GitLabUsername(s string) error {
	if !gitLabName(s) {
		return fmt.Errorf("invalid GitLab username %s", Quote(s))
	}
	return nil
}

// GitLabProjectID validates a numeric project ID in canonical decimal form
// (no sign, no leading zero), the only way a project is addressed in a URL.
func GitLabProjectID(s string) error {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
		return fmt.Errorf("invalid GitLab project id %s", Quote(s))
	}
	return nil
}

// MergeRequestIID validates a merge request IID (its number inside the project)
// and returns it.
func MergeRequestIID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, fmt.Errorf("invalid merge request iid %s", Quote(s))
	}
	return uint32(n), nil
}

// GitLabTimestamp parses a GitLab time after the Unix epoch, in UTC.
func GitLabTimestamp(s string) (time.Time, error) {
	if len(s) <= gitLabTimestampMax {
		for _, layout := range gitLabTimestampLayouts {
			if t, err := time.Parse(layout, s); err == nil && t.Unix() > 0 {
				return t.UTC(), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %s", Quote(s))
}

// GitLabURL validates PREVIEWD_GITLAB_URL with the rules of GHESURL: https,
// a host, no user info, path, query or fragment.
func GitLabURL(s string) (string, error) { return forgeURL("GitLab", s) }

// ParseGitLabApprovers parses PREVIEWD_APPROVERS for GitLab:
// comma-separated group[/subgroup]/project:username#id entries, with the
// guarantees of ParseApprovers.
func ParseGitLabApprovers(s string) (map[string][]Approver, error) {
	return parseApprovers(s, GitLabProjectPath, func(login string) error {
		if len(login) > maxStoredLoginLen {
			return fmt.Errorf("GitLab username %s exceeds the %d bytes an approver is recorded with", Quote(login), maxStoredLoginLen)
		}
		return GitLabUsername(login)
	})
}

// GitLabEventUUID validates X-Gitlab-Event-UUID, the identifier GitLab gives
// one hook event, and returns its canonical lower-case form: the replay key.
// Only the canonical 8-4-4-4-12 form is accepted, of any UUID version.
func GitLabEventUUID(s string) (string, error) {
	if len(s) != 36 {
		return "", fmt.Errorf("invalid event uuid %s", Quote(s))
	}
	for i := range len(s) {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return "", fmt.Errorf("invalid event uuid %s", Quote(s))
			}
		default:
			if !isHex(s[i]) {
				return "", fmt.Errorf("invalid event uuid %s", Quote(s))
			}
		}
	}
	return strings.ToLower(s), nil
}
