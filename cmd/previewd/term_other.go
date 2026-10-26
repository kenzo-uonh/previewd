//go:build !linux

package main

import (
	"errors"
	"os"
)

// hideInput fails closed: a terminal's echo is only turned off on Linux, so
// a secret is never read from a terminal elsewhere.
func hideInput(*os.File) (func() error, bool, error) {
	return nil, true, errors.New("reading a secret from a terminal requires Linux: pipe it instead")
}
