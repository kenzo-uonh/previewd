package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// DefaultStagingDir is the host directory, backed by ramfs, under which each
// environment's secrets are staged as one file per key.
const DefaultStagingDir = "/run/previewd/secrets"

const (
	// Inside the container the staged directory is read-only (bind mount) and
	// world-readable, so a non-root image user can read its secrets. On the
	// host, the 0700 staging root keeps every other account out.
	stagedDirMode  os.FileMode = 0o555
	stagedFileMode os.FileMode = 0o444
	writeDirMode   os.FileMode = 0o700
	writeFileMode  os.FileMode = 0o600
)

var (
	// One path element, usable as a file name in the container.
	secretKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// One path element, DNS-label shaped like the container name.
	envIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Stager writes secrets to a memory-backed host directory, one sub-directory
// per environment, for a read-only bind mount into the environment container.
// Secret values never reach the Docker API, the container config on disk, or
// an image layer.
type Stager struct {
	dir     string
	checkFS func(path string) error
}

// NewStager verifies the staging root and returns a Stager. It fails closed:
// the root must be a real directory owned by this process's user, closed to
// group and other, and on ramfs (tmpfs only with allowTmpfs, since tmpfs pages
// can be swapped to disk).
func NewStager(dir string, allowTmpfs bool) (*Stager, error) {
	return newStager(dir, func(path string) error {
		return checkStagingFS(path, allowTmpfs)
	})
}

func newStager(dir string, checkFS func(string) error) (*Stager, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("secret staging dir %q must be an absolute path", dir)
	}
	dir = filepath.Clean(dir)

	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat secret staging dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secret staging dir %q is not a directory (symlinks refused)", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("secret staging dir %q has mode %#o, want no group/other access", dir, perm)
	}
	if err := checkOwner(info); err != nil {
		return nil, fmt.Errorf("secret staging dir %q: %w", dir, err)
	}
	if err := checkFS(dir); err != nil {
		return nil, err
	}

	return &Stager{dir: dir, checkFS: checkFS}, nil
}

// Stage writes secrets for envID and returns the host directory to bind-mount.
// A previous staging for envID is replaced. On any error nothing is left
// behind for envID. Errors name keys, never values.
func (s *Stager) Stage(envID string, secrets map[string]string) (string, error) {
	if !envIDPattern.MatchString(envID) {
		return "", fmt.Errorf("stage secrets: invalid environment id %q", envID)
	}
	for key := range secrets {
		if !secretKeyPattern.MatchString(key) {
			return "", fmt.Errorf("stage secrets for %s: invalid secret key %q", envID, key)
		}
	}

	// The mount may have changed since startup: re-verify before every write.
	if err := s.checkFS(s.dir); err != nil {
		return "", fmt.Errorf("stage secrets for %s: %w", envID, err)
	}

	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return "", fmt.Errorf("open secret staging root: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	if err := removeStaged(root, envID); err != nil {
		return "", fmt.Errorf("clear previous staging for %s: %w", envID, err)
	}

	if err := writeStaged(root, envID, secrets); err != nil {
		if rmErr := removeStaged(root, envID); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("clean up partial staging: %w", rmErr))
		}
		return "", fmt.Errorf("stage secrets for %s: %w", envID, err)
	}

	return filepath.Join(s.dir, envID), nil
}

// Remove deletes the staged secrets of envID. It is idempotent.
func (s *Stager) Remove(envID string) error {
	if !envIDPattern.MatchString(envID) {
		return fmt.Errorf("remove staged secrets: invalid environment id %q", envID)
	}

	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return fmt.Errorf("open secret staging root: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	if err := removeStaged(root, envID); err != nil {
		return fmt.Errorf("remove staged secrets for %s: %w", envID, err)
	}
	return nil
}

func writeStaged(root *os.Root, envID string, secrets map[string]string) error {
	if err := root.Mkdir(envID, writeDirMode); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	for key, value := range secrets {
		name := filepath.Join(envID, key)
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, writeFileMode)
		if err != nil {
			return fmt.Errorf("create secret file %s: %w", key, err)
		}
		_, writeErr := f.WriteString(value)
		closeErr := f.Close()
		if writeErr != nil {
			return fmt.Errorf("write secret file %s: %w", key, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close secret file %s: %w", key, closeErr)
		}
		if err := root.Chmod(name, stagedFileMode); err != nil {
			return fmt.Errorf("chmod secret file %s: %w", key, err)
		}
	}

	if err := root.Chmod(envID, stagedDirMode); err != nil {
		return fmt.Errorf("chmod staging dir: %w", err)
	}
	return nil
}

func removeStaged(root *os.Root, envID string) error {
	// A staged directory is 0555: restore write access so its entries can be
	// unlinked. A missing directory is not an error.
	if err := root.Chmod(envID, writeDirMode); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("chmod staging dir: %w", err)
	}
	if err := root.RemoveAll(envID); err != nil {
		return fmt.Errorf("remove staging dir: %w", err)
	}
	return nil
}
