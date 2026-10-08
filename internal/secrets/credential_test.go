package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github-app-key"), []byte("PEM"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	got, err := Credential("github-app-key")
	if err != nil || string(got) != "PEM" {
		t.Fatalf("Credential = %q, %v", got, err)
	}
}

// Fail closed: a name that is a path, a link, a directory, an empty or
// oversized file, or no credentials directory, is refused.
func TestCredentialRefuses(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	for name, content := range map[string]string{"empty": "", "big": strings.Repeat("k", maxCredentialBytes+1)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(outside, []byte("PEM"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	// A link that stays inside the directory: os.Root would follow it,
	// the regular-file check does not.
	if err := os.WriteFile(filepath.Join(dir, "real"), []byte("PEM"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "inner-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	for _, name := range []string{"", ".", "..", "../secret", "/etc/passwd", "a/b", "link", "inner-link", "subdir", "empty", "big", "missing",
		strings.Repeat("a", 65), "key\x00"} {
		if got, err := Credential(name); err == nil {
			t.Errorf("Credential(%q) = %q, want an error", name, got)
		}
	}
	for _, env := range []string{"", "relative/dir"} {
		t.Setenv("CREDENTIALS_DIRECTORY", env)
		if _, err := Credential("key"); err == nil {
			t.Errorf("CREDENTIALS_DIRECTORY=%q accepted", env)
		}
	}
}
