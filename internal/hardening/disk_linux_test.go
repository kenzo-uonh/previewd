package hardening

import (
	"path/filepath"
	"testing"
)

func TestFreeDiskBytes(t *testing.T) {
	free, err := FreeDiskBytes(t.TempDir())
	if err != nil || free <= 0 {
		t.Fatalf("FreeDiskBytes(temp dir) = %d, %v; want a positive size", free, err)
	}
}

// Fail closed: a path that cannot be read, or is not clean and absolute,
// gives no size.
func TestFreeDiskBytesRefuses(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"", "relative", dir + "/../" + filepath.Base(dir), filepath.Join(dir, "missing")} {
		if free, err := FreeDiskBytes(p); err == nil {
			t.Errorf("FreeDiskBytes(%q) = %d, nil; want an error", p, free)
		}
	}
}
