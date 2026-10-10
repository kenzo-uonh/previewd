package vcs

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
)

var (
	commitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// FetchRepository checks out exactly commitSHA of cloneURL into destDir, the
// fallback of Fetcher when no GitHub App is configured (H2): a shallow fetch
// of that one commit, never a branch, a tag or the history (gitCommands).
func FetchRepository(ctx context.Context, cloneURL, commitSHA, destDir string) error {
	if !commitSHAPattern.MatchString(commitSHA) {
		return fmt.Errorf("invalid commit SHA format: untrusted input")
	}

	parsedURL, err := url.ParseRequestURI(cloneURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http" && parsedURL.Scheme != "file") {
		return fmt.Errorf("invalid repository clone URL scheme")
	}

	if err := os.MkdirAll(destDir, 0750); err != nil {
		return fmt.Errorf("failed to create build directory: %w", err)
	}

	for _, args := range gitCommands(parsedURL.String(), commitSHA) {
		// #nosec G204 -- fixed argument vectors (gitCommands): cloneURL parsed by url.ParseRequestURI, commitSHA matched by commitSHAPattern.
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = destDir
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git %s failed: %w", args[0], err)
		}
	}
	return nil
}

// gitCommands is the git invocation of FetchRepository, in order: an empty
// repository, the remote, a fetch of the one commit at depth 1 by its SHA,
// and the checkout of what was fetched (FETCH_HEAD, never a branch).
func gitCommands(cloneURL, commitSHA string) [][]string {
	return [][]string{
		{"init"},
		{"remote", "add", "origin", cloneURL},
		{"fetch", "--depth=1", "origin", commitSHA},
		{"checkout", "FETCH_HEAD"},
	}
}
