//go:build !linux

package main

import "errors"

// raiseMemlock fails closed: memory is only locked on Linux.
func raiseMemlock() error { return errors.New("locking memory requires Linux") }
