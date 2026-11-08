package main

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns the slave side of a new pseudo-terminal, or skips.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("cannot unlock the pseudo-terminal: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return slave
}

func echoOn(t *testing.T, f *os.File) bool {
	t.Helper()
	tio, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return tio.Lflag&unix.ECHO != 0
}

func TestHideInputTurnsTheEchoOffAndBack(t *testing.T) {
	tty := openPTY(t)
	if !echoOn(t, tty) {
		t.Fatal("a new terminal starts with the echo on")
	}
	restore, terminal, err := hideInputGuarded(tty, []os.Signal{syscall.SIGUSR2}, func(os.Signal) { t.Error("no signal was sent") })
	if err != nil || !terminal {
		t.Fatalf("terminal %v, %v", terminal, err)
	}
	if echoOn(t, tty) {
		t.Error("the echo is still on")
	}
	if err := restore(); err != nil || !echoOn(t, tty) {
		t.Errorf("restore: %v, echo on %v", err, echoOn(t, tty))
	}
	if err := restore(); err != nil {
		t.Errorf("restore twice: %v", err)
	}

	// Not a terminal: nothing changes, the caller reads a pipe.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if _, terminal, err := hideInput(r); terminal || err != nil {
		t.Errorf("a pipe: terminal %v, %v", terminal, err)
	}
}

// A signal that ends the command while the echo is off puts it back first,
// then lets the signal take its default action.
func TestHideInputRestoresTheEchoOnASignal(t *testing.T) {
	tty := openPTY(t)
	died := make(chan os.Signal, 1)
	restore, _, err := hideInputGuarded(tty, []os.Signal{syscall.SIGUSR2}, func(sig os.Signal) {
		// The echo must be back before the signal is handed on.
		if !echoOn(t, tty) {
			t.Error("the signal was handed on with the echo still off")
		}
		died <- sig
	})
	if err != nil {
		t.Fatal(err)
	}
	if echoOn(t, tty) {
		t.Fatal("the echo is still on")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	select {
	case sig := <-died:
		if sig != syscall.SIGUSR2 {
			t.Errorf("signal %v", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the signal did not restore the echo")
	}
	if !echoOn(t, tty) {
		t.Error("the echo is still off after the signal")
	}
	_ = restore() // the command is ending: restoring again is harmless
}

// Once restored, the guard is gone: the signals are not intercepted any more.
func TestHideInputGuardEndsAtRestore(t *testing.T) {
	tty := openPTY(t)
	restore, _, err := hideInputGuarded(tty, []os.Signal{syscall.SIGUSR2}, func(os.Signal) { t.Error("the guard outlived restore") })
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	// Give a mistakenly live goroutine time to run before the test ends;
	// SIGUSR2 is not sent (its default action would end the test binary).
	time.Sleep(50 * time.Millisecond)
}
