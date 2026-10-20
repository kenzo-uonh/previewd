package hardening

import (
	"errors"
	"io/fs"
	"os"
	"testing"
)

func TestClassifyStagingMount(t *testing.T) {
	const uid = 998
	good := stagingState{magic: ramfsMagic, mounted: true, mode: fs.ModeDir | 0o700, uid: uid}
	if err := classifyStagingMount("/run/previewd/secrets", good, uid); err != nil {
		t.Fatalf("a ramfs mount, 0700, owned by the user: %v", err)
	}

	for name, mutate := range map[string]func(*stagingState){
		"tmpfs (swappable)":     func(s *stagingState) { s.magic = tmpfsMagic },
		"ext4":                  func(s *stagingState) { s.magic = 0xEF53 },
		"not a mount point":     func(s *stagingState) { s.mounted = false },
		"mode 0750":             func(s *stagingState) { s.mode = fs.ModeDir | 0o750 },
		"mode 0755":             func(s *stagingState) { s.mode = fs.ModeDir | 0o755 },
		"mode 0770":             func(s *stagingState) { s.mode = fs.ModeDir | 0o770 },
		"sticky bit":            func(s *stagingState) { s.mode |= fs.ModeSticky },
		"setgid bit":            func(s *stagingState) { s.mode |= fs.ModeSetgid },
		"owned by root":         func(s *stagingState) { s.uid = 0 },
		"owned by someone else": func(s *stagingState) { s.uid = uid + 1 },
		"a symlink":             func(s *stagingState) { s.mode = fs.ModeSymlink | 0o700 },
		"a regular file":        func(s *stagingState) { s.mode = 0o700 },
	} {
		s := good
		mutate(&s)
		err := classifyStagingMount("/run/previewd/secrets", s, uid)
		if !errors.Is(err, ErrStagingMount) {
			t.Errorf("%s: err = %v, want ErrStagingMount", name, err)
		}
	}
}

// Fail closed on the real file system: a temp directory is neither ramfs nor
// a mount point, a missing path cannot be read, and a path that is not clean
// and absolute is not looked at.
func TestCheckStagingMountRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a temp dir":   dir,
		"missing":      dir + "/missing",
		"relative":     "run/previewd/secrets",
		"not clean":    dir + "/../secrets",
		"empty":        "",
		"filesystem /": "/",
	} {
		if err := CheckStagingMount(path, os.Getuid()); !errors.Is(err, ErrStagingMount) {
			t.Errorf("%s: err = %v, want ErrStagingMount", name, err)
		}
	}
}
