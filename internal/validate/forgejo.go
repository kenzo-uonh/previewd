package validate

import (
	"fmt"
	"strings"
)

// Forgejo and Gitea identifiers (V1.2 spec 3.1). A repository is
// owner/name as on GitHub, but Forgejo spells names with its own rules: an
// owner (a user or an organization) is a username, a repository name is any
// run of letters, digits, '-', '_' and '.'.
const (
	// maxForgejoNameLen is Forgejo's limit on a username and on an
	// organization name.
	maxForgejoNameLen = 40
	// maxForgejoRepoNameLen is Forgejo's limit on a repository name.
	maxForgejoRepoNameLen = 100
)

// forgejoUsername checks a Forgejo username or organization name: letters,
// digits, '-', '_' and '.', starting with a letter or a digit, never two of
// '-', '_', '.' in a row and never one at the end (Forgejo's own rules).
func forgejoUsername(s string) bool {
	if s == "" || len(s) > maxForgejoNameLen {
		return false
	}
	prevSpecial := false
	for i := range len(s) {
		c := s[i]
		alnum := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		special := c == '-' || c == '_' || c == '.'
		switch {
		case !alnum && !special, special && (i == 0 || prevSpecial):
			return false
		}
		prevSpecial = special
	}
	return !prevSpecial
}

// forgejoRepoName checks a Forgejo repository name: 1 to 100 of letters,
// digits, '-', '_' and '.', not "." or "..", not ending with ".git" or
// ".wiki" (Forgejo refuses both: a name must not read as a git directory or
// as the repository's wiki).
func forgejoRepoName(s string) bool {
	if s == "" || len(s) > maxForgejoRepoNameLen || s == "." || s == ".." {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return !strings.HasSuffix(s, ".git") && !strings.HasSuffix(s, ".wiki")
}

// ForgejoRepoFullName validates a Forgejo "owner/repository", at most the
// 140 bytes the queue keeps.
func ForgejoRepoFullName(s string) error {
	owner, name, ok := strings.Cut(s, "/")
	if !ok || len(s) > maxStoredRepoLen || !forgejoUsername(owner) || !forgejoRepoName(name) {
		return fmt.Errorf("invalid Forgejo repository name %s", Quote(s))
	}
	return nil
}

// ForgejoUsername validates a Forgejo username, at most the 39 bytes the
// queue and the audit trail keep: Forgejo allows 40, an account with a
// 40-byte name is refused where it enters. As with a GitHub login, it names
// an account for logs and the audit trail only: identity is the ID.
func ForgejoUsername(s string) error {
	if len(s) > maxStoredLoginLen || !forgejoUsername(s) {
		return fmt.Errorf("invalid Forgejo username %s", Quote(s))
	}
	return nil
}

// ForgejoURL validates PREVIEWD_FORGEJO_URL with the rules of GHESURL:
// https, a host, no user info, path, query or fragment. A Forgejo served
// under a sub-path is not supported.
func ForgejoURL(s string) (string, error) { return forgeURL("Forgejo", s) }

// ParseForgejoApprovers parses PREVIEWD_APPROVERS for Forgejo:
// comma-separated owner/repo:username#id entries, with the guarantees of
// ParseApprovers.
func ParseForgejoApprovers(s string) (map[string][]Approver, error) {
	return parseApprovers(s, ForgejoRepoFullName, ForgejoUsername)
}
