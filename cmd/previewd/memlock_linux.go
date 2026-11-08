package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// raiseMemlock lifts RLIMIT_MEMLOCK to unlimited, which LockMemory requires.
// root (CAP_SYS_RESOURCE) can; another user can only when its hard limit is
// already unlimited. The daemon gets the limit from its unit instead
// (LimitMEMLOCK=infinity).
func raiseMemlock() error {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		return fmt.Errorf("raise RLIMIT_MEMLOCK to unlimited: %w", err)
	}
	return nil
}
