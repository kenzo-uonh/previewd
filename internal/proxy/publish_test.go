package proxy

import (
	"bytes"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"gopkg.in/yaml.v3"
)

func testRoute(backend string) Route {
	return Route{
		EnvID:   envid.Generate("acme/shop", "feature/login", 42),
		Domain:  "preview.example",
		Backend: netip.MustParseAddrPort(backend),
	}
}

// System test: Traefik never reads a torn document. Readers poll the route
// file while the publisher alternates between two documents of different
// sizes; every read must be exactly one of the two complete documents, and
// the file never disappears between swaps.
func TestPublishSwapIsAtomicForConcurrentReaders(t *testing.T) {
	dir := t.TempDir()
	p, err := NewPublisher(dir)
	if err != nil {
		t.Fatal(err)
	}
	routes := []Route{testRoute("10.0.0.2:8080"), testRoute("[fd00:1234:5678:9abc:def0:1234:5678:9abc]:65535")}
	docs := make([][]byte, len(routes))
	for i, r := range routes {
		if docs[i], err = Render(r); err != nil {
			t.Fatal(err)
		}
	}
	if len(docs[0]) == len(docs[1]) {
		t.Fatal("test documents must differ in size to expose torn reads")
	}
	if err := p.Publish(routes[0]); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, RouteFile(routes[0].EnvID))
	var stop atomic.Bool
	var reads atomic.Int64
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for !stop.Load() {
				got, err := os.ReadFile(path)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, docs[0]) && !bytes.Equal(got, docs[1]) {
					errs <- errors.New("torn read: " + string(got))
					return
				}
				var doc Document
				if err := yaml.Unmarshal(got, &doc); err != nil {
					errs <- err
					return
				}
				reads.Add(1)
			}
		})
	}

	// Each Publish fsyncs twice (file, directory); 300 swaps keep the test
	// fast on slow disks while readers still overlap every swap.
	for i := range 300 {
		if err := p.Publish(routes[i%2]); err != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("Publish: %v", err)
		}
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if reads.Load() == 0 {
		t.Fatal("readers made no observation")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != RouteFile(routes[0].EnvID) {
		t.Fatalf("routes dir holds %v, want only the route document (no temporary files)", entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != routeFileMode {
		t.Fatalf("route file mode %#o, want %#o", info.Mode().Perm(), routeFileMode)
	}
}

type recorder struct {
	calls   []string
	failOn  string
	created string
}

func (r *recorder) step(name string) error {
	r.calls = append(r.calls, name)
	if name == r.failOn {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

type recordedFile struct {
	r    *recorder
	name string
}

func (f recordedFile) Name() string                       { return f.name }
func (f recordedFile) Write(b []byte) (int, error)        { return len(b), f.r.step("write") }
func (f recordedFile) Chmod(fs.FileMode) error            { return f.r.step("chmod") }
func (f recordedFile) Sync() error                        { return f.r.step("fsync-file") }
func (f recordedFile) Close() error                       { return f.r.step("close") }
func (r *recorder) Rename(string, string) error           { return r.step("rename") }
func (r *recorder) Remove(name string) error              { return r.step("remove " + filepath.Base(name)) }
func (r *recorder) SyncDir(string) error                  { return r.step("fsync-dir") }
func (r *recorder) ReadDir(string) ([]fs.DirEntry, error) { return nil, r.step("readdir") }
func (r *recorder) CreateTemp(dir, pattern string) (tempFile, error) {
	r.created = filepath.Join(dir, strings.Replace(pattern, "*", "123", 1))
	return recordedFile{r: r, name: r.created}, r.step("create")
}

// Durability: the file is fsynced before the rename, and the directory
// after it. A failure before the rename removes the temporary file and
// leaves the published document untouched.
func TestWriteAtomicOrderAndCleanup(t *testing.T) {
	want := "create write chmod fsync-file close rename fsync-dir"
	r := &recorder{}
	if err := writeAtomic(r, "/routes", "pr-1-0123456789.yml", []byte("doc")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, " "); got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if !strings.HasPrefix(filepath.Base(r.created), ".") || strings.HasSuffix(r.created, ".yml") {
		t.Fatalf("temporary file %q could be loaded by Traefik (*.yml)", r.created)
	}

	for _, failOn := range []string{"write", "chmod", "fsync-file", "close", "rename"} {
		r := &recorder{failOn: failOn}
		if err := writeAtomic(r, "/routes", "pr-1-0123456789.yml", []byte("doc")); err == nil {
			t.Fatalf("failure in %s not reported", failOn)
		}
		calls := strings.Join(r.calls, " ")
		if !strings.HasSuffix(calls, "remove "+filepath.Base(r.created)) {
			t.Errorf("failure in %s: temporary file not removed (calls %q)", failOn, calls)
		}
		if failOn != "rename" && strings.Contains(calls, "rename") {
			t.Errorf("failure in %s: renamed anyway (calls %q)", failOn, calls)
		}
	}

	r = &recorder{failOn: "fsync-dir"}
	if err := writeAtomic(r, "/routes", "pr-1-0123456789.yml", []byte("doc")); err == nil {
		t.Fatal("directory fsync failure not reported")
	}
}

func TestPublisherRemoveIsIdempotentAndValidates(t *testing.T) {
	dir := t.TempDir()
	p, err := NewPublisher(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := testRoute("10.0.0.2:8080")
	if err := p.Publish(r); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.Remove(r.EnvID); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, RouteFile(r.EnvID))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("route survived Remove: %v", err)
	}
	for _, bad := range []string{"../x", "pr-1", "", "a/b"} {
		if err := p.Remove(bad); err == nil {
			t.Errorf("Remove accepted %q", bad)
		}
	}
}

func TestNewPublisherRefusesBadDirs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"relative", filepath.Join(t.TempDir(), "absent"), file, link} {
		if _, err := NewPublisher(dir); err == nil {
			t.Errorf("NewPublisher accepted %q", dir)
		}
	}
}

// Inventory keeps route documents of valid environments and removes every
// other file Traefik could load, including crash debris; a non-regular entry
// refuses the inventory.
func TestInventoryCollectsOrphans(t *testing.T) {
	dir := t.TempDir()
	p, err := NewPublisher(dir)
	if err != nil {
		t.Fatal(err)
	}
	backend := netip.MustParseAddrPort("172.31.0.2:8080")
	for _, env := range []string{"pr-1-0a0a0a0a0a", "pr-2-0b0b0b0b0b"} {
		if err := p.Publish(Route{EnvID: env, Domain: "local.previewd", Backend: backend}); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		".pr-3-0c0c0c0c0c.yml.tmp-123": "partial",  // interrupted Publish
		"injected.yml":                 "http: {}", // foreign route document
		"Pr-4-0d0d0d0d0d.yml":          "http: {}", // not a valid environment ID
		"pr-5-0e0e0e0e0e.yaml":         "http: {}", // other extension Traefik loads
		"middlewares.toml":             "",
		".hidden.yml":                  "",
		"README":                       "kept: Traefik ignores it",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	routes, removed, err := p.Inventory()
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	slices.Sort(routes)
	slices.Sort(removed)
	if want := []string{"pr-1-0a0a0a0a0a", "pr-2-0b0b0b0b0b"}; !slices.Equal(routes, want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	wantRemoved := []string{".hidden.yml", ".pr-3-0c0c0c0c0c.yml.tmp-123", "Pr-4-0d0d0d0d0d.yml", "injected.yml", "middlewares.toml", "pr-5-0e0e0e0e0e.yaml"}
	if !slices.Equal(removed, wantRemoved) {
		t.Fatalf("removed = %v, want %v", removed, wantRemoved)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if want := []string{"README", "pr-1-0a0a0a0a0a.yml", "pr-2-0b0b0b0b0b.yml"}; !slices.Equal(left, want) {
		t.Fatalf("left on disk = %v, want %v", left, want)
	}
}

func TestInventoryRefusesNonRegularEntries(t *testing.T) {
	for name, mk := range map[string]func(dir string) error{
		"directory": func(dir string) error { return os.Mkdir(filepath.Join(dir, "nested"), 0o755) },
		"symlink":   func(dir string) error { return os.Symlink("/etc/passwd", filepath.Join(dir, "pr-1-0a0a0a0a0a.yml")) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := mk(dir); err != nil {
				t.Fatal(err)
			}
			p, err := NewPublisher(dir)
			if err != nil {
				t.Fatal(err)
			}
			if routes, _, err := p.Inventory(); err == nil {
				t.Fatalf("Inventory accepted a %s (routes %v)", name, routes)
			}
		})
	}
}
