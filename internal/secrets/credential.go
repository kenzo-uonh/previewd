package secrets

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

// maxCredentialBytes bounds one credential (a PEM private key).
const maxCredentialBytes = 64 << 10

// Credential reads the systemd credential name from $CREDENTIALS_DIRECTORY:
// LoadCredential= or LoadCredentialEncrypted= in the unit decrypts it onto a
// non-swappable, per-service mount, never a file previewd writes. name is a
// credential name, not a path: anything but [A-Za-z0-9._-]{1,64} (and "."
// or "..") is refused, and the read cannot leave the directory. Without a
// credentials directory (the daemon not run by systemd, or the unit not
// passing the credential) the read fails: there is no fallback to a path.
func Credential(name string) ([]byte, error) {
	if err := validate.CredentialName(name); err != nil {
		return nil, err
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("CREDENTIALS_DIRECTORY is not set to an absolute path: pass the credential with LoadCredential= in the unit")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open credentials directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("credential %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential %s is not a regular file (%s)", name, info.Mode().Type())
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("credential %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read credential %s: %w", name, err)
	}
	if len(data) > maxCredentialBytes {
		clear(data)
		return nil, fmt.Errorf("credential %s exceeds %d bytes", name, maxCredentialBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("credential %s is empty: %w", name, fs.ErrNotExist)
	}
	return data, nil
}
