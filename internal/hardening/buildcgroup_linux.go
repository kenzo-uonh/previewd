package hardening

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// cgroupRoot is where the unified cgroup v2 hierarchy is mounted.
const cgroupRoot = "/sys/fs/cgroup/"

// NewBuildCgroup refuses dir unless it is a clean absolute path strictly
// under /sys/fs/cgroup on a cgroup2 file system: the limits checked are
// those of cgroup v2, which the egress and build bounds need.
func NewBuildCgroup(dir string) (*BuildCgroup, error) {
	if dir != filepath.Clean(dir) || !strings.HasPrefix(dir, cgroupRoot) || len(dir) == len(cgroupRoot) {
		return nil, fmt.Errorf("%w: %q is not a clean path under %s", ErrBuildCgroup, dir, cgroupRoot)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return nil, fmt.Errorf("%w: statfs %s: %w", ErrBuildCgroup, dir, err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("%w: %s is not on cgroup v2 (file system magic %#x)", ErrBuildCgroup, dir, st.Type)
	}
	return &BuildCgroup{dir: dir}, nil
}
