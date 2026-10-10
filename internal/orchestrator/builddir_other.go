//go:build !linux

package orchestrator

import (
	"errors"
	"io/fs"
)

// ownedByProcess fails closed outside Linux: the startup sweep then
// refuses to start rather than guess what it may remove.
func ownedByProcess(fs.FileInfo) (bool, error) {
	return false, errors.New("file ownership is checked on Linux only")
}
