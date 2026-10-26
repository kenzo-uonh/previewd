package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// echoSignals end a command that is reading a secret with the echo off:
// the terminal is put back first.
func echoSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}
}

// hideInput turns off the echo of f when it is a terminal, so a secret typed
// there never shows. terminal is false, and nothing changes, when f is not a
// terminal (a pipe, a file). restore puts the echo back; so does a signal
// that ends the command first (the signal then takes its default action), so
// that a Ctrl-C never leaves the operator's terminal silent.
func hideInput(f *os.File) (restore func() error, terminal bool, err error) {
	return hideInputGuarded(f, echoSignals(), reraise)
}

func hideInputGuarded(f *os.File, sigs []os.Signal, die func(os.Signal)) (restore func() error, terminal bool, err error) {
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
	putBack := func() error { return unix.IoctlSetTermios(fd, unix.TCSETS, saved) }
	stop := restoreOnSignal(putBack, sigs, die)
	return func() error {
		stop()
		return putBack()
	}, true, nil
}

// restoreOnSignal waits for one of sigs. When it arrives before stop is
// called, putBack runs and die is called with the signal. stop ends the
// wait and gives the signals back to their default action.
func restoreOnSignal(putBack func() error, sigs []os.Signal, die func(os.Signal)) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case sig := <-ch:
			if err := putBack(); err != nil {
				fmt.Fprintf(os.Stderr, "previewd: restore the terminal echo: %v (run: stty echo)\n", err)
			}
			signal.Stop(ch)
			die(sig)
		case <-done:
		}
	}()
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}

// reraise hands sig back to its default action, which ends the process.
func reraise(sig os.Signal) {
	s, ok := sig.(syscall.Signal)
	if !ok {
		os.Exit(1)
	}
	signal.Reset(sig)
	if err := syscall.Kill(os.Getpid(), s); err != nil {
		os.Exit(128 + int(s))
	}
	select {} // the signal is on its way
}
