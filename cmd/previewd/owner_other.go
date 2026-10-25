//go:build !linux

package main

import "errors"

// adoptOwner fails closed: previewd restores databases on Linux only.
func adoptOwner(string, string, int, func(string, int, int) error) error {
	return errors.New("restore requires Linux")
}
