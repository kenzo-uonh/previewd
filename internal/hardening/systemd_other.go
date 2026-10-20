//go:build !linux

package hardening

import (
	"context"
	"errors"
)

// SystemctlShow fails closed: unit properties are read on Linux hosts only.
func SystemctlShow(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("systemd unit properties require Linux")
}
