//go:build !linux

package hardening

import "errors"

// LockMemory fails closed: memory locking is verified on Linux only.
func LockMemory() error {
	return errors.New("memory locking requires Linux")
}

// LockedMemoryKB fails closed outside Linux.
func LockedMemoryKB() (int64, error) {
	return 0, errors.New("memory locking requires Linux")
}
