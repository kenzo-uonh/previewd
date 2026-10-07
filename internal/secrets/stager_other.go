//go:build !linux

package secrets

import (
	"fmt"
	"io/fs"
)

// checkStagingFS fails closed: memory-backed staging is verified on Linux only.
func checkStagingFS(_ string, _ bool) error {
	return fmt.Errorf("secret staging requires Linux ramfs")
}

func checkOwner(_ fs.FileInfo) error {
	return fmt.Errorf("secret staging requires Linux")
}
