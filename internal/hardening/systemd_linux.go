package hardening

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// maxSystemctlBytes bounds one systemctl reply.
const maxSystemctlBytes = 64 << 10

// systemctlPaths are tried in order: a fixed location, never $PATH, so the
// answer to "is the filter active" cannot come from a planted binary.
func systemctlPaths() []string { return []string{"/usr/bin/systemctl", "/bin/systemctl"} }

// SystemctlShow runs `systemctl show -p PROP ... -- UNIT` with an empty
// environment (but LC_ALL=C) and returns its standard output.
func SystemctlShow(ctx context.Context, unit string, props ...string) ([]byte, error) {
	if unit == "" || strings.HasPrefix(unit, "-") || len(props) == 0 {
		return nil, fmt.Errorf("systemctl show: invalid unit %q or no property", unit)
	}
	bin := ""
	for _, p := range systemctlPaths() {
		if _, err := os.Stat(p); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, errors.New("systemctl not found (is this a systemd host?)")
	}
	args := []string{"show"}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	args = append(args, "--", unit)

	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- a fixed binary; the unit is a constant of the caller, not input
	cmd.Env = []string{"LC_ALL=C"}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, maxSystemctlBytes+1))
	waitErr := cmd.Wait()
	switch {
	case readErr != nil:
		return nil, fmt.Errorf("systemctl show %s: read: %w", unit, readErr)
	case len(out) > maxSystemctlBytes:
		return nil, fmt.Errorf("systemctl show %s: reply over %d bytes", unit, maxSystemctlBytes)
	case waitErr != nil:
		return nil, fmt.Errorf("systemctl show %s: %w", unit, waitErr)
	}
	return out, nil
}
