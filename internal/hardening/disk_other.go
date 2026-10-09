//go:build !linux

package hardening

import "errors"

// FreeDiskBytes fails closed: the free-disk floor is verified on Linux only.
func FreeDiskBytes(string) (int64, error) {
	return 0, errors.New("free disk: requires Linux")
}
