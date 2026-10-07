package secrets

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Filesystem magic numbers from linux/magic.h.
const (
	ramfsMagic int64 = 0x858458f6
	tmpfsMagic int64 = 0x01021994
)

// checkStagingFS refuses any staging directory that is not memory-backed.
func checkStagingFS(path string, allowTmpfs bool) error {
	magic, err := statfsMagic(path)
	if err != nil {
		return err
	}
	return classifyStagingFS(magic, allowTmpfs)
}

func statfsMagic(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs secret staging dir: %w", err)
	}
	// On 32-bit targets f_type is int32 and ramfs's magic reads negative: the
	// comparison fails and staging is refused, which is the safe outcome.
	return int64(st.Type), nil
}

func classifyStagingFS(magic int64, allowTmpfs bool) error {
	switch magic {
	case ramfsMagic:
		return nil
	case tmpfsMagic:
		if allowTmpfs {
			return nil
		}
		return fmt.Errorf("secret staging dir is tmpfs, whose pages can be swapped to disk: mount ramfs, or set PREVIEWD_ALLOW_TMPFS_SECRETS=1 on a host without swap")
	default:
		return fmt.Errorf("secret staging dir is not memory-backed (filesystem magic %#x): mount ramfs on it", magic)
	}
}

func checkOwner(info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read owner")
	}
	if euid := os.Geteuid(); int64(st.Uid) != int64(euid) {
		return fmt.Errorf("owned by uid %d, want uid %d (the previewd user)", st.Uid, euid)
	}
	return nil
}
