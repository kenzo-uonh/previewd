package hardening

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// BuildCgroup is the host view of PREVIEWD_BUILDKIT_CGROUP: the cgroup v2
// subtree, bounded by the deployment drop-in, where the engine runs every
// BuildKit RUN step (D-V1-4). Its limits are read on the host because a RUN
// in a private cgroup namespace sees its own memory.max as "max" even under
// a limited parent. NewBuildCgroup checks that dir is a cgroup2 mount.
type BuildCgroup struct {
	dir string
}

// maxCgroupFileBytes bounds one interface file of the subtree.
const maxCgroupFileBytes = 64 << 10

// ErrBuildCgroup is a limit, placement or read failure of the subtree.
var ErrBuildCgroup = errors.New("build cgroup check failed")

// Dir is the subtree's absolute path.
func (c *BuildCgroup) Dir() string { return c.dir }

// CheckLimits fails unless memory.max, pids.max and the quota of cpu.max
// are finite positive integers and memory.swap.max is exactly 0. A missing
// or unreadable file fails.
func (c *BuildCgroup) CheckLimits() error {
	for _, name := range []string{"memory.max", "pids.max"} {
		v, err := c.read(name)
		if err != nil {
			return err
		}
		if err := finite(name, v); err != nil {
			return err
		}
	}
	cpu, err := c.read("cpu.max")
	if err != nil {
		return err
	}
	quota, _, _ := strings.Cut(cpu, " ")
	if err := finite("cpu.max quota", quota); err != nil {
		return err
	}
	swap, err := c.read("memory.swap.max")
	if err != nil {
		return err
	}
	if swap != "0" {
		return fmt.Errorf("%w: %s/memory.swap.max is %q, want 0", ErrBuildCgroup, c.dir, swap)
	}
	return nil
}

func finite(name, v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return fmt.Errorf("%w: %s is %q, want a finite limit", ErrBuildCgroup, name, v)
	}
	return nil
}

// read returns the trimmed content of one interface file of the subtree.
func (c *BuildCgroup) read(name string) (string, error) {
	b, err := readBounded(filepath.Join(c.dir, name))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrBuildCgroup, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a file of the configured cgroup subtree
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCgroupFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(b) > maxCgroupFileBytes {
		return nil, fmt.Errorf("read %s: more than %d bytes", path, maxCgroupFileBytes)
	}
	return b, nil
}

// Procs returns the processes of the subtree, every descendant cgroup
// included. A child cgroup removed during the walk (a RUN step ending) is
// skipped; any other error fails.
func (c *BuildCgroup) Procs() ([]int, error) {
	var pids []int
	err := filepath.WalkDir(c.dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path != c.dir && errors.Is(walkErr, fs.ErrNotExist) {
				return fs.SkipDir
			}
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		b, err := readBounded(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			if path != c.dir && errors.Is(err, fs.ErrNotExist) {
				return fs.SkipDir
			}
			return err
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			pid, err := strconv.Atoi(line)
			if err != nil || pid <= 0 {
				return fmt.Errorf("%s/cgroup.procs: invalid PID %q", path, sc.Text())
			}
			pids = append(pids, pid)
		}
		return sc.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("%w: processes of %s: %w", ErrBuildCgroup, c.dir, err)
	}
	return pids, nil
}
