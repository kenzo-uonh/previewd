package secrets

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestClassifyStagingFS(t *testing.T) {
	const ext4Magic int64 = 0xef53

	cases := []struct {
		name       string
		magic      int64
		allowTmpfs bool
		wantErr    bool
	}{
		{"ramfs", ramfsMagic, false, false},
		{"tmpfs refused by default", tmpfsMagic, false, true},
		{"tmpfs with explicit opt-in", tmpfsMagic, true, false},
		{"disk refused", ext4Magic, false, true},
		{"disk refused even with tmpfs opt-in", ext4Magic, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyStagingFS(tc.magic, tc.allowTmpfs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("classifyStagingFS(%#x, %v) error = %v, wantErr %v", tc.magic, tc.allowTmpfs, err, tc.wantErr)
			}
		})
	}
}

func TestNewStagerRefusesDiskBackedTempDir(t *testing.T) {
	root := stagingRoot(t)
	magic, err := statfsMagic(root)
	if err != nil {
		t.Fatal(err)
	}
	if magic == ramfsMagic || magic == tmpfsMagic {
		t.Skipf("test temp dir is memory-backed (%#x); disk refusal not observable here", magic)
	}
	if _, err := NewStager(root, true); err == nil {
		t.Fatalf("NewStager accepted a disk-backed directory (magic %#x)", magic)
	}
}

const nsHelperEnv = "PREVIEWD_SECRETS_NS_HELPER"

// System test: the stager on a real ramfs mount, a real tmpfs mount and the
// disk. The test re-executes itself as root of a fresh user + mount
// namespace (unshare), so it mounts filesystems without host privileges.
// Where user namespaces are unavailable it skips, unless
// PREVIEWD_REQUIRE_NS_TESTS=1 (CI), which turns the skip into a failure.
func TestStagerOnRealMounts(t *testing.T) {
	if err := exec.Command("unshare", "--user", "--map-root-user", "--mount", "true").Run(); err != nil {
		msg := fmt.Sprintf("unprivileged user+mount namespaces unavailable: %v", err)
		if os.Getenv("PREVIEWD_REQUIRE_NS_TESTS") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}

	cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--", // #nosec G204 -- the test binary itself
		os.Args[0], "-test.run=^TestStagerOnRealMountsHelper$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), nsHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestStagerOnRealMountsHelper") {
		t.Fatalf("namespace helper failed: %v\n%s", err, out)
	}
}

func TestStagerOnRealMountsHelper(t *testing.T) {
	if os.Getenv(nsHelperEnv) != "1" {
		t.Skip("namespace helper only")
	}

	mountAt := func(fstype string) string {
		dir := filepath.Join(t.TempDir(), fstype)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(fstype, dir, fstype, syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "mode=0700"); err != nil {
			t.Fatalf("mount %s: %v", fstype, err)
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(dir, 0); err != nil {
				t.Errorf("unmount %s: %v", fstype, err)
			}
		})
		return dir
	}

	ramfs := mountAt("ramfs")
	if magic, err := statfsMagic(ramfs); err != nil || magic != ramfsMagic {
		t.Fatalf("statfs(ramfs) = %#x, %v", magic, err)
	}
	s, err := NewStager(ramfs, false)
	if err != nil {
		t.Fatalf("NewStager refused a real ramfs mount: %v", err)
	}
	dir, err := s.Stage("pr-7-0123456789", map[string]string{"TOKEN": "v"})
	if err != nil {
		t.Fatalf("Stage on ramfs: %v", err)
	}
	if magic, err := statfsMagic(dir); err != nil || magic != ramfsMagic {
		t.Fatalf("staged dir is not on ramfs: %#x, %v", magic, err)
	}
	if err := s.Remove("pr-7-0123456789"); err != nil {
		t.Fatal(err)
	}

	tmpfs := mountAt("tmpfs")
	if _, err := NewStager(tmpfs, false); err == nil {
		t.Fatal("NewStager accepted tmpfs without the opt-in")
	}
	if _, err := NewStager(tmpfs, true); err != nil {
		t.Fatalf("NewStager refused tmpfs with the opt-in: %v", err)
	}

	// The mount disappears after startup: the next job must be refused.
	gone := mountAt("ramfs")
	s, err = NewStager(gone, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Unmount(gone, 0); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("tmpfs", gone, "tmpfs", 0, "mode=0700"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stage("pr-7-0123456789", map[string]string{"TOKEN": "v"}); err == nil {
		t.Fatal("Stage wrote to tmpfs after the ramfs mount was replaced")
	}
}
