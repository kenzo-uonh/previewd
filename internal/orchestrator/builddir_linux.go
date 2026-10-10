package orchestrator

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// ownedByProcess reports whether fi, from os.Lstat, belongs to the
// process's effective user.
func ownedByProcess(fi fs.FileInfo) (bool, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return false, errors.New("no stat data")
	}
	return int64(st.Uid) == int64(os.Geteuid()), nil
}
