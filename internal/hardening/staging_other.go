//go:build !linux

package hardening

import "errors"

// ErrStagingMount is a secret staging root that is not a private ramfs
// mount owned by the daemon's user.
var ErrStagingMount = errors.New("secret staging mount check failed")

// CheckStagingMount fails closed: the staging mount is verified on Linux only.
func CheckStagingMount(string, int) error {
	return errors.Join(ErrStagingMount, errors.New("requires Linux"))
}
