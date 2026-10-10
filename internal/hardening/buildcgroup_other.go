//go:build !linux

package hardening

import "fmt"

// NewBuildCgroup fails closed: build bounds are verified on Linux cgroup v2.
func NewBuildCgroup(dir string) (*BuildCgroup, error) {
	return nil, fmt.Errorf("%w: %q: build bounds require Linux cgroup v2", ErrBuildCgroup, dir)
}
