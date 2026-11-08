package hardening

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const coreHelperEnv = "PREVIEWD_HARDENING_CORE_HELPER"

// runCoreHelper re-executes the test binary: RLIMIT_CORE and the dumpable
// flag stay out of the test process.
func runCoreHelper(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoreHelperProcess$", "-test.count=1") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), coreHelperEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %s: %v\n%s", mode, err, out)
	}
	return string(out)
}

func TestCoreHelperProcess(t *testing.T) {
	mode := os.Getenv(coreHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	switch mode {
	case "untouched":
		// A process that never asked: dumpable, so verification refuses.
		fmt.Printf("HELPER-RESULT verify-refused=%v\n", VerifyCoreDumpsDisabled() != nil)
	case "limit-only":
		// RLIMIT_CORE at 0 is not enough: the process is still dumpable and
		// a debugger-readable /proc/<pid>/mem.
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
			fmt.Println("HELPER-ERR setrlimit:", err)
			os.Exit(2)
		}
		fmt.Printf("HELPER-RESULT verify-refused=%v\n", VerifyCoreDumpsDisabled() != nil)
	case "soft-only":
		// A soft limit of 0 under a raisable hard limit is not a control.
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
			fmt.Println("HELPER-ERR getrlimit:", err)
			os.Exit(2)
		}
		rl.Cur, rl.Max = 0, 1<<20
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &rl); err != nil {
			fmt.Println("HELPER-ERR setrlimit:", err)
			os.Exit(2)
		}
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			fmt.Println("HELPER-ERR prctl:", err)
			os.Exit(2)
		}
		fmt.Printf("HELPER-RESULT verify-refused=%v\n", VerifyCoreDumpsDisabled() != nil)
	case "disable":
		if err := DisableCoreDumps(); err != nil {
			fmt.Println("HELPER-ERR DisableCoreDumps:", err)
			os.Exit(2)
		}
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
			fmt.Println("HELPER-ERR getrlimit:", err)
			os.Exit(2)
		}
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil {
			fmt.Println("HELPER-ERR prctl:", err)
			os.Exit(2)
		}
		// The daemon reads /proc/self/status after this (VmLck): it must
		// still work with a non-dumpable process.
		_, statusErr := LockedMemoryKB()
		// A child keeps the zero limit.
		child, childErr := exec.Command("/bin/sh", "-c", "ulimit -c").Output()
		raise := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1 << 20, Max: 1 << 20})
		fmt.Printf("HELPER-RESULT cur=%d max=%d dumpable=%d statusErr=%v child=%q childErr=%v uid=%d raised=%v\n",
			rl.Cur, rl.Max, dumpable, statusErr, strings.TrimSpace(string(child)), childErr, os.Getuid(), raise == nil)
	}
	os.Exit(0)
}

func TestDisableCoreDumps(t *testing.T) {
	out := runCoreHelper(t, "disable")
	if !strings.Contains(out, "HELPER-RESULT cur=0 max=0 dumpable=0 statusErr=<nil> child=\"0\" childErr=<nil>") {
		t.Fatalf("want RLIMIT_CORE 0/0, not dumpable, /proc/self/status readable and a child limited to 0:\n%s", out)
	}
	// Only root (CAP_SYS_RESOURCE) can raise a lowered hard limit.
	if !strings.Contains(out, "uid=0") && !strings.Contains(out, "raised=false") {
		t.Fatalf("an unprivileged process raised its hard RLIMIT_CORE again:\n%s", out)
	}
}

// Fail closed: a limit alone, or a soft limit alone, is not verified.
func TestVerifyCoreDumpsDisabledRefusesHalfMeasures(t *testing.T) {
	for _, mode := range []string{"untouched", "limit-only", "soft-only"} {
		if out := runCoreHelper(t, mode); !strings.Contains(out, "HELPER-RESULT verify-refused=true") {
			t.Errorf("%s: verification accepted a process that can still dump core:\n%s", mode, out)
		}
	}
}
