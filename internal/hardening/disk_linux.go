package hardening

import (
	"fmt"
	"math"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// FreeDiskBytes is the space an unprivileged writer can still use on the
// file system holding path (statfs f_bavail × f_bsize): the Docker data
// root, for the deploy's free-disk floor (V1-I9). path must be a clean
// absolute path; statfs reads the file system, never path's content.
func FreeDiskBytes(path string) (int64, error) {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return 0, fmt.Errorf("free disk: %q is not a clean absolute path", path)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("free disk: statfs %s: %w", path, err)
	}
	if st.Bsize <= 0 {
		return 0, fmt.Errorf("free disk: statfs %s: block size %d", path, st.Bsize)
	}
	bsize := uint64(st.Bsize) // #nosec G115 -- checked positive above
	if st.Bavail > math.MaxInt64/bsize {
		return math.MaxInt64, nil
	}
	return int64(st.Bavail * bsize), nil // #nosec G115 -- bounded by MaxInt64 above
}
