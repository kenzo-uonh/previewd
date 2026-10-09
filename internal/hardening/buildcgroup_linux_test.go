package hardening

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// NewBuildCgroup refuses anything but a clean path under /sys/fs/cgroup
// on a cgroup2 file system.
func TestNewBuildCgroupFailsClosed(t *testing.T) {
	for _, dir := range []string{
		"", "relative", "/sys/fs/cgroup", "/sys/fs/cgroup/", "/sys/fs/cgroup/a/../../b",
		"/sys/fs/cgroup/a/", "/tmp", t.TempDir(),
		"/sys/fs/cgroup/previewd-test-does-not-exist",
	} {
		if c, err := NewBuildCgroup(dir); !errors.Is(err, ErrBuildCgroup) {
			t.Errorf("NewBuildCgroup(%q) = %v, %v", dir, c, err)
		}
	}
}

// On the host's own hierarchy: a cgroup2 directory is accepted, any other
// file system under /sys/fs/cgroup (a cgroup v1 controller) refused.
func TestNewBuildCgroupChecksTheFileSystem(t *testing.T) {
	entries, err := os.ReadDir("/sys/fs/cgroup")
	if err != nil {
		t.Skipf("no cgroup hierarchy: %v", err)
	}
	tested := 0
	for _, e := range entries {
		dir := filepath.Join("/sys/fs/cgroup", e.Name())
		var st unix.Statfs_t
		if !e.IsDir() || unix.Statfs(dir, &st) != nil {
			continue
		}
		tested++
		c, err := NewBuildCgroup(dir)
		if st.Type == unix.CGROUP2_SUPER_MAGIC {
			if err != nil || c.Dir() != dir {
				t.Errorf("cgroup2 %s refused: %v", dir, err)
			}
		} else if !errors.Is(err, ErrBuildCgroup) {
			t.Errorf("%s (magic %#x) accepted", dir, st.Type)
		}
	}
	if tested == 0 {
		t.Skip("no directory under /sys/fs/cgroup")
	}
}
