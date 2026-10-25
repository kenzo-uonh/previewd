package hardening

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

// ShowFunc returns what `systemctl show -p PROP ... UNIT` prints for unit:
// one Property=value line per requested property. SystemctlShow is the
// host's; tests and the doctor inject their own.
type ShowFunc func(ctx context.Context, unit string, props ...string) ([]byte, error)

// parseShow reads systemctl show output into a property map. A line with
// no '=' is not systemctl's output: the whole reply is refused rather than
// partly trusted.
func parseShow(out []byte) (map[string]string, error) {
	props := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("unexpected systemctl output line %q", line)
		}
		props[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read systemctl output: %w", err)
	}
	return props, nil
}

// ErrMemlock is a memory-lock limit or probe that does not let the daemon
// lock its memory.
var ErrMemlock = errors.New("memory lock check failed")

// unlimited are the spellings systemctl gives an unlimited resource limit.
func unlimited(v string) bool { return v == "infinity" || v == "18446744073709551615" }

// CheckUnitMemlock fails unless unit's LimitMEMLOCK is infinity: the
// daemon (LockMemory) refuses to start with a finite RLIMIT_MEMLOCK, since
// MCL_FUTURE would make the Go runtime abort once the limit is reached. It
// reads the unit, not the caller's shell: a root shell is bound by its own
// limit (or not at all, through CAP_IPC_LOCK), never by the unit's.
func CheckUnitMemlock(ctx context.Context, show ShowFunc, unit string) error {
	out, err := show(ctx, unit, "LimitMEMLOCK")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrMemlock, unit, err)
	}
	props, err := parseShow(out)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrMemlock, unit, err)
	}
	if v := props["LimitMEMLOCK"]; !unlimited(v) {
		return fmt.Errorf("%w: %s has LimitMEMLOCK=%q, want infinity", ErrMemlock, unit, v)
	}
	return nil
}
