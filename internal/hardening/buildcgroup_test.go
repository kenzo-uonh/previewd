package hardening

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeCgroup writes files under a temp dir standing for the subtree; a
// value "" leaves the file out.
func fakeCgroup(t *testing.T, files map[string]string) *BuildCgroup {
	t.Helper()
	dir := t.TempDir()
	for name, v := range files {
		if v == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &BuildCgroup{dir: dir}
}

func bounded() map[string]string {
	return map[string]string{
		"memory.max":      "4294967296\n",
		"memory.swap.max": "0\n",
		"pids.max":        "2048\n",
		"cpu.max":         "200000 100000\n",
		"cgroup.procs":    "",
	}
}

func TestBuildCgroupLimits(t *testing.T) {
	if err := fakeCgroup(t, bounded()).CheckLimits(); err != nil {
		t.Fatalf("bounded subtree refused: %v", err)
	}
	for name, change := range map[string][2]string{
		"memory unbounded":   {"memory.max", "max\n"},
		"memory missing":     {"memory.max", ""},
		"memory zero":        {"memory.max", "0\n"},
		"memory garbage":     {"memory.max", "4G\n"},
		"swap allowed":       {"memory.swap.max", "max\n"},
		"swap finite":        {"memory.swap.max", "1048576\n"},
		"swap missing":       {"memory.swap.max", ""},
		"tasks unbounded":    {"pids.max", "max\n"},
		"tasks missing":      {"pids.max", ""},
		"tasks negative":     {"pids.max", "-1\n"},
		"cpu unbounded":      {"cpu.max", "max 100000\n"},
		"cpu missing":        {"cpu.max", ""},
		"cpu empty":          {"cpu.max", "\n"},
		"memory too large":   {"memory.max", strings.Repeat("9", maxCgroupFileBytes+1)},
		"memory overflowing": {"memory.max", "99999999999999999999\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files := bounded()
			files[change[0]] = change[1]
			if err := fakeCgroup(t, files).CheckLimits(); !errors.Is(err, ErrBuildCgroup) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

// Procs reads every cgroup.procs of the subtree, descendants included.
func TestBuildCgroupProcs(t *testing.T) {
	files := bounded()
	files["cgroup.procs"] = "\n"
	files["buildkit/cgroup.procs"] = ""
	files["buildkit/run-1/cgroup.procs"] = "101\n102\n"
	files["buildkit/run-2/deep/cgroup.procs"] = "203\n"
	c := fakeCgroup(t, files)
	if err := os.WriteFile(filepath.Join(c.dir, "buildkit", "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, "buildkit", "run-2", "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	pids, err := c.Procs()
	slices.Sort(pids)
	if err != nil || !slices.Equal(pids, []int{101, 102, 203}) {
		t.Fatalf("Procs = %v, %v", pids, err)
	}

	empty := fakeCgroup(t, map[string]string{"cgroup.procs": "\n"})
	if pids, err := empty.Procs(); err != nil || len(pids) != 0 {
		t.Fatalf("idle subtree = %v, %v", pids, err)
	}
	for name, files := range map[string]map[string]string{
		"invalid PID":  {"cgroup.procs": "12x\n"},
		"zero PID":     {"cgroup.procs": "0\n"},
		"root missing": {"cgroup.procs": ""},
	} {
		t.Run(name, func(t *testing.T) {
			if pids, err := fakeCgroup(t, files).Procs(); !errors.Is(err, ErrBuildCgroup) {
				t.Fatalf("Procs = %v, %v", pids, err)
			}
		})
	}
	gone := &BuildCgroup{dir: filepath.Join(t.TempDir(), "gone")}
	if _, err := gone.Procs(); !errors.Is(err, ErrBuildCgroup) {
		t.Fatalf("missing subtree: %v", err)
	}
}
