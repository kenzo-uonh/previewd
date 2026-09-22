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

// FetchRepository securely clones a specific commit SHA into an ephemeral host directory.
func FetchRepository(ctx context.Context, cloneURL, commitSHA, destDir string) error {
	if !commitSHAPattern.MatchString(commitSHA) {
		return fmt.Errorf("invalid commit SHA format: untrusted input")
	}

	parsedURL, err := url.ParseRequestURI(cloneURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
		return fmt.Errorf("invalid or non-HTTP(S) repository clone URL")
	}

	if err := os.MkdirAll(destDir, 0750); err != nil {
		return fmt.Errorf("failed to create build directory: %w", err)
	}

	// #nosec G204 -- Static execution string.
	initCmd := exec.CommandContext(ctx, "git", "init")
	initCmd.Dir = destDir
	if err := initCmd.Run(); err != nil {
		return fmt.Errorf("git init failed: %w", err)
	}

	// #nosec G204 -- cloneURL validated via url.ParseRequestURI.
	remoteCmd := exec.CommandContext(ctx, "git", "remote", "add", "origin", parsedURL.String())
	remoteCmd.Dir = destDir
	if err := remoteCmd.Run(); err != nil {
		return fmt.Errorf("git remote add failed: %w", err)
	}

	// #nosec G204 -- commitSHA validated via commitSHAPattern regex.
	fetchCmd := exec.CommandContext(ctx, "git", "fetch", "--depth=1", "origin", commitSHA)
	fetchCmd.Dir = destDir
	if err := fetchCmd.Run(); err != nil {
		return fmt.Errorf("git fetch failed: %w", err)
	}

	// #nosec G204 -- Static execution string.
	checkoutCmd := exec.CommandContext(ctx, "git", "checkout", "FETCH_HEAD")
	checkoutCmd.Dir = destDir
	if err := checkoutCmd.Run(); err != nil {
		return fmt.Errorf("git checkout failed: %w", err)
	}

	return nil
}
