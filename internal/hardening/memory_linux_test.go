package hardening

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const helperEnv = "PREVIEWD_HARDENING_HELPER"

// runHelper re-executes the test binary so mlockall and rlimit changes stay
// out of the test process.
func runHelper(t *testing.T, mode string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "-test.count=1") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		fmt.Println("HELPER-ERR getrlimit:", err)
		os.Exit(2)
	}
	switch mode {
	case "finite":
		rl.Cur = 64 << 10
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
			fmt.Println("HELPER-ERR setrlimit:", err)
			os.Exit(2)
		}
		err := LockMemory()
		kb, kbErr := LockedMemoryKB()
		fmt.Printf("HELPER-RESULT err=%v vmlck=%d kbErr=%v\n", err != nil, kb, kbErr)
	case "unlimited":
		rl.Cur = rl.Max
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
			fmt.Println("HELPER-ERR setrlimit:", err)
			os.Exit(2)
		}
		if err := LockMemory(); err != nil {
			fmt.Println("HELPER-ERR LockMemory:", err)
			os.Exit(2)
		}
		before, err := LockedMemoryKB()
		if err != nil {
			fmt.Println("HELPER-ERR VmLck:", err)
			os.Exit(2)
		}
		// MCL_FUTURE: a fresh 32 MiB allocation must be locked too.
		buf := make([]byte, 32<<20)
		for i := range buf {
			buf[i] = byte(i)
		}
		after, err := LockedMemoryKB()
		if err != nil {
			fmt.Println("HELPER-ERR VmLck:", err)
			os.Exit(2)
		}
		fmt.Printf("HELPER-RESULT before=%d after=%d sum=%d\n", before, after, buf[len(buf)-1])
	}
	os.Exit(0)
}

// Fail closed: with a finite RLIMIT_MEMLOCK, LockMemory refuses before
// calling mlockall, so the process neither locks nor risks aborting later.
func TestLockMemoryRefusesFiniteLimit(t *testing.T) {
	out, err := runHelper(t, "finite")
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if !strings.Contains(out, "HELPER-RESULT err=true vmlck=0 kbErr=<nil>") {
		t.Fatalf("finite limit: want refusal and no locked memory, got:\n%s", out)
	}
}

// With an unlimited RLIMIT_MEMLOCK, current pages are locked and so are pages
// allocated afterwards. Needs a hard limit of infinity (systemd
// LimitMEMLOCK=infinity, or `sudo prlimit --memlock=unlimited:unlimited`).
// PREVIEWD_REQUIRE_MLOCK_TEST=1 turns the skip into a failure (CI).
func TestLockMemoryLocksCurrentAndFuturePages(t *testing.T) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Max != unix.RLIM_INFINITY {
		msg := fmt.Sprintf("hard RLIMIT_MEMLOCK is %d bytes; the success path needs unlimited", rl.Max)
		if os.Getenv("PREVIEWD_REQUIRE_MLOCK_TEST") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}

	out, err := runHelper(t, "unlimited")
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	var before, after, sum int64
	idx := strings.Index(out, "HELPER-RESULT")
	if idx < 0 {
		t.Fatalf("no helper result:\n%s", out)
	}
	if _, err := fmt.Sscanf(out[idx:], "HELPER-RESULT before=%d after=%d sum=%d", &before, &after, &sum); err != nil {
		t.Fatalf("parse helper output: %v\n%s", err, out)
	}
	if before == 0 {
		t.Fatal("VmLck is 0 after LockMemory")
	}
	if after-before < 30<<10 {
		t.Fatalf("VmLck grew by %d kB after a 32 MiB allocation: MCL_FUTURE not in effect", after-before)
	}
}

func TestLockedMemoryKBReadsProcStatus(t *testing.T) {
	if _, err := LockedMemoryKB(); err != nil {
		t.Fatal(err)
	}
}
