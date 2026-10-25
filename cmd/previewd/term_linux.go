package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// hideInput turns off the echo of f when it is a terminal, so a secret typed
// there never shows. terminal is false, and nothing changes, when f is not a
// terminal (a pipe, a file). restore puts the echo back.
func hideInput(f *os.File) (restore func() error, terminal bool, err error) {
	fd := int(f.Fd()) // #nosec G115 -- a file descriptor fits an int
	saved, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() error { return nil }, false, nil
	}
	hidden := *saved
	hidden.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &hidden); err != nil {
		return nil, true, fmt.Errorf("turn off the terminal echo: %w", err)
	}
	return func() error { return unix.IoctlSetTermios(fd, unix.TCSETS, saved) }, true, nil
}
