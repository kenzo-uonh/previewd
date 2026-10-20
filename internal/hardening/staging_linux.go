package hardening

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ErrStagingMount is a secret staging root that is not a private ramfs
// mount owned by the daemon's user.
var ErrStagingMount = errors.New("secret staging mount check failed")

// Filesystem magic numbers from linux/magic.h. secrets.NewStager checks the
// same two at the daemon's start; the doctor checks them from outside,
// before the daemon runs, and must tell tmpfs (swappable) from ramfs.
const (
	ramfsMagic int64 = 0x858458f6
	tmpfsMagic int64 = 0x01021994
)

// stagingState is what CheckStagingMount observed about the directory.
type stagingState struct {
	magic   int64
	mounted bool // its device differs from its parent's: a mount point
	mode    fs.FileMode
	uid     uint32
}

// CheckStagingMount verifies that dir is the mount point of a ramfs, mode
// 0700 exactly, owned by uid: the ramfs the daemon stages secrets on (never
// swapped, unlike tmpfs), unreadable by anyone else, and the mount unit's
// work (run-previewd-secrets.mount) done before the daemon starts. dir
// must be a clean absolute path and not a symbolic link.
func CheckStagingMount(dir string, uid int) error {
	if !filepath.IsAbs(dir) || dir != filepath.Clean(dir) {
		return fmt.Errorf("%w: %q is not a clean absolute path", ErrStagingMount, dir)
	}
	var st, parent unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return fmt.Errorf("%w: stat %s: %w", ErrStagingMount, dir, err)
	}
	if err := unix.Lstat(filepath.Dir(dir), &parent); err != nil {
		return fmt.Errorf("%w: stat parent of %s: %w", ErrStagingMount, dir, err)
	}
	var fsst unix.Statfs_t
	if err := unix.Statfs(dir, &fsst); err != nil {
		return fmt.Errorf("%w: statfs %s: %w", ErrStagingMount, dir, err)
	}
	return classifyStagingMount(dir, stagingState{
		// On 32-bit targets f_type is int32 and ramfs's magic reads negative:
		// the comparison fails, which is the safe outcome.
		magic:   int64(fsst.Type),
		mounted: st.Dev != parent.Dev,
		mode:    fileMode(st.Mode),
		uid:     st.Uid,
	}, uid)
}

// fileMode converts a stat mode to an fs.FileMode, keeping only what the
// check reads: the type, the permission bits and sticky, setuid, setgid.
func fileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFREG:
	default:
		mode |= fs.ModeIrregular
	}
	if m&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	if m&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	return mode
}

func classifyStagingMount(dir string, s stagingState, uid int) error {
	switch {
	case !s.mode.IsDir():
		return fmt.Errorf("%w: %s is not a directory (%s)", ErrStagingMount, dir, s.mode.Type())
	case s.magic == tmpfsMagic:
		return fmt.Errorf("%w: %s is tmpfs, whose pages can be swapped to disk: mount ramfs (run-previewd-secrets.mount)", ErrStagingMount, dir)
	case s.magic != ramfsMagic:
		return fmt.Errorf("%w: %s is not memory-backed (filesystem magic %#x): mount ramfs (run-previewd-secrets.mount)", ErrStagingMount, dir, s.magic)
	case !s.mounted:
		return fmt.Errorf("%w: %s is a directory of its parent's file system, not a mount point", ErrStagingMount, dir)
	case s.mode != fs.ModeDir|0o700:
		return fmt.Errorf("%w: %s has mode %s, want drwx------", ErrStagingMount, dir, s.mode)
	case uid < 0 || int64(s.uid) != int64(uid):
		return fmt.Errorf("%w: %s is owned by uid %d, want uid %d (the previewd user)", ErrStagingMount, dir, s.uid, uid)
	}
	return nil
}
