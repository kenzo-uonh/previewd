package hardening

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// DisableCoreDumps makes sure this process can never write its memory to a
// file: RLIMIT_CORE is set to zero (soft and hard, so nothing raises it
// again) and PR_SET_DUMPABLE to 0, which also refuses ptrace and
// /proc/<pid>/mem to every other unprivileged process. A secret held in
// (locked) memory is then not one crash away from a core file on
// persistent disk. Both settings are read back: success is verified, not
// assumed. Children keep the zero limit; the dumpable flag is reset by
// execve, so they are unaffected.
func DisableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("set RLIMIT_CORE to 0: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE 0: %w", err)
	}
	return VerifyCoreDumpsDisabled()
}

// VerifyCoreDumpsDisabled reports an error unless the process cannot dump
// core: RLIMIT_CORE is 0 (soft and hard) and the process is not dumpable.
func VerifyCoreDumpsDisabled() error {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		return fmt.Errorf("read RLIMIT_CORE: %w", err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		return fmt.Errorf("RLIMIT_CORE is %d/%d bytes (soft/hard), want 0/0", rl.Cur, rl.Max)
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("prctl PR_GET_DUMPABLE: %w", err)
	}
	if dumpable != 0 {
		return errors.New("the process is still dumpable after PR_SET_DUMPABLE 0")
	}
	return nil
}
