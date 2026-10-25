package hardening

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// LockMemory pins every current and future page of the process in RAM
// (mlockall MCL_CURRENT|MCL_FUTURE), so secrets held in memory never reach
// swap. It refuses unless RLIMIT_MEMLOCK is unlimited: with a finite limit,
// MCL_FUTURE makes allocations fail once the limit is reached and the Go
// runtime aborts. Success is verified through VmLck, not assumed.
func LockMemory() error {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return fmt.Errorf("read RLIMIT_MEMLOCK: %w", err)
	}
	if rl.Cur != unix.RLIM_INFINITY {
		return fmt.Errorf("RLIMIT_MEMLOCK is %d bytes, want unlimited (systemd: LimitMEMLOCK=infinity)", rl.Cur)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("mlockall: %w", err)
	}
	kb, err := LockedMemoryKB()
	if err != nil {
		return fmt.Errorf("verify mlockall: %w", err)
	}
	if kb == 0 {
		return errors.New("verify mlockall: VmLck is 0 kB after a successful call")
	}
	return nil
}

// LockedMemoryKB returns the process's locked memory (VmLck) in kB.
func LockedMemoryKB() (int64, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/status: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		fields := bytes.Fields(sc.Bytes())
		if len(fields) == 3 && string(fields[0]) == "VmLck:" && string(fields[2]) == "kB" {
			kb, err := strconv.ParseInt(string(fields[1]), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse VmLck: %w", err)
			}
			return kb, nil
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("scan /proc/self/status: %w", err)
	}
	return 0, errors.New("VmLck not found in /proc/self/status")
}

// ProbeMlockall asks the kernel whether this process may lock its memory:
// mlockall(MCL_CURRENT), then munlockall. EPERM or ENOMEM is the limit
// (RLIMIT_MEMLOCK) or a missing CAP_IPC_LOCK. It locks nothing for good
// and is not LockMemory: it never sets MCL_FUTURE and does not require an
// unlimited limit.
func ProbeMlockall() error {
	if err := unix.Mlockall(unix.MCL_CURRENT); err != nil {
		return fmt.Errorf("mlockall: %w", err)
	}
	if err := unix.Munlockall(); err != nil {
		return fmt.Errorf("munlockall: %w", err)
	}
	return nil
}
