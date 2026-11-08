//go:build !linux

package hardening

import "errors"

// DisableCoreDumps fails closed: core dump suppression is verified on Linux
// only.
func DisableCoreDumps() error {
	return errors.New("core dump suppression requires Linux")
}

// VerifyCoreDumpsDisabled fails closed outside Linux.
func VerifyCoreDumpsDisabled() error {
	return errors.New("core dump suppression requires Linux")
}
