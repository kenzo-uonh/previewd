package secrets

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecretValue = "s3cr3t-value-never-in-errors"

func memoryFS(string) error { return nil }

func stagingRoot(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Staged directories are 0555; t.TempDir cleanup cannot unlink their
	// entries. Registered after TempDir, so it runs before it.
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return dir
}

func newTestStager(t *testing.T) *Stager {
	t.Helper()
	s, err := newStager(stagingRoot(t), memoryFS)
	if err != nil {
		t.Fatalf("newStager: %v", err)
	}
	return s
}

func TestStageWritesOneReadOnlyFilePerKey(t *testing.T) {
	s := newTestStager(t)

	dir, err := s.Stage("pr-7", map[string]string{"DB_PASSWORD": testSecretValue, "API_KEY": "k"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if want := filepath.Join(s.dir, "pr-7"); dir != want {
		t.Fatalf("Stage dir = %q, want %q", dir, want)
	}

	got, err := os.ReadFile(filepath.Join(dir, "DB_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testSecretValue {
		t.Fatalf("DB_PASSWORD content = %q, want %q", got, testSecretValue)
	}

	for name, want := range map[string]os.FileMode{"": stagedDirMode, "DB_PASSWORD": stagedFileMode, "API_KEY": stagedFileMode} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != want {
			t.Errorf("mode of %q = %#o, want %#o", name, perm, want)
		}
	}
}

func TestStageReplacesPreviousStaging(t *testing.T) {
	s := newTestStager(t)

	if _, err := s.Stage("pr-7", map[string]string{"OLD": "1"}); err != nil {
		t.Fatal(err)
	}
	dir, err := s.Stage("pr-7", map[string]string{"NEW": "2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "OLD")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale secret OLD survived restaging: %v", err)
	}
}

func TestStageRejectsUnsafeKeysWithoutWriting(t *testing.T) {
	s := newTestStager(t)

	for _, key := range []string{"../escape", "a/b", "", ".hidden", "WITH SPACE", "1LEADING_DIGIT"} {
		_, err := s.Stage("pr-7", map[string]string{"OK": "x", key: testSecretValue})
		if err == nil {
			t.Fatalf("Stage accepted key %q", key)
		}
		if strings.Contains(err.Error(), testSecretValue) {
			t.Fatalf("error leaks the secret value: %v", err)
		}
	}

	if _, err := os.Stat(filepath.Join(s.dir, "pr-7")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging dir created despite invalid key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.dir), "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path traversal wrote outside the staging root: %v", err)
	}
}

func TestStageRejectsUnsafeEnvIDs(t *testing.T) {
	s := newTestStager(t)

	for _, id := range []string{"", ".", "..", "../pr-7", "pr/7", "PR-7", "-pr", strings.Repeat("a", 64)} {
		if _, err := s.Stage(id, map[string]string{"K": "v"}); err == nil {
			t.Errorf("Stage accepted env id %q", id)
		}
		if err := s.Remove(id); err == nil {
			t.Errorf("Remove accepted env id %q", id)
		}
	}
}

func TestStageFailsClosedWhenStorageIsNotMemoryBacked(t *testing.T) {
	root := stagingRoot(t)
	onDisk := false
	s, err := newStager(root, func(string) error {
		if onDisk {
			return errors.New("not memory-backed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The mount disappears after startup: the next job must be refused.
	onDisk = true
	if _, err := s.Stage("pr-7", map[string]string{"K": testSecretValue}); err == nil {
		t.Fatal("Stage wrote secrets to a non-memory-backed directory")
	}
	if _, err := os.Stat(filepath.Join(root, "pr-7")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging dir created on refused storage: %v", err)
	}
}

func TestNewStagerFailsClosed(t *testing.T) {
	t.Run("not memory-backed", func(t *testing.T) {
		if _, err := newStager(stagingRoot(t), func(string) error { return errors.New("disk") }); err == nil {
			t.Fatal("accepted a non-memory-backed root")
		}
	})
	t.Run("relative path", func(t *testing.T) {
		if _, err := newStager("run/previewd/secrets", memoryFS); err == nil {
			t.Fatal("accepted a relative root")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := newStager(filepath.Join(t.TempDir(), "absent"), memoryFS); err == nil {
			t.Fatal("accepted a missing root")
		}
	})
	t.Run("group or other access", func(t *testing.T) {
		root := stagingRoot(t)
		if err := os.Chmod(root, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := newStager(root, memoryFS); err == nil {
			t.Fatal("accepted a root readable by group")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := stagingRoot(t)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		if _, err := newStager(link, memoryFS); err == nil {
			t.Fatal("accepted a symlinked root")
		}
	})
	t.Run("regular file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := newStager(file, memoryFS); err == nil {
			t.Fatal("accepted a regular file")
		}
	})
}

func TestRemoveIsIdempotent(t *testing.T) {
	s := newTestStager(t)

	if _, err := s.Stage("pr-7", map[string]string{"K": "v"}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Remove("pr-7"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(s.dir, "pr-7")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged dir survived Remove: %v", err)
	}
}
