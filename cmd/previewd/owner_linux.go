package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// adoptOwner gives path the owner of reference, or of its directory when
// reference does not exist, when the caller is root (euid 0): a database
// restored by root and left root-owned, mode 0600, is closed to the daemon.
// A non-root caller creates files it owns already and changes nothing.
func adoptOwner(path, reference string, euid int, chown func(path string, uid, gid int) error) error {
	if euid != 0 {
		return nil
	}
	fi, err := os.Stat(reference)
	if errors.Is(err, fs.ErrNotExist) {
		fi, err = os.Stat(filepath.Dir(reference))
	}
	if err != nil {
		return fmt.Errorf("read the owner to give %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read the owner to give %s: no owner information", path)
	}
	if err := chown(path, int(st.Uid), int(st.Gid)); err != nil {
		return fmt.Errorf("give %s to uid %d gid %d: %w", path, st.Uid, st.Gid, err)
	}
	return nil
}
