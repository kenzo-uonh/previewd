package proxy

import (
	"bytes"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
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

func (f recordedFile) Name() string                { return f.name }
func (f recordedFile) Write(b []byte) (int, error) { return len(b), f.r.step("write") }
func (f recordedFile) Chmod(fs.FileMode) error     { return f.r.step("chmod") }
func (f recordedFile) Sync() error                 { return f.r.step("fsync-file") }
func (f recordedFile) Close() error                { return f.r.step("close") }
func (r *recorder) Rename(string, string) error    { return r.step("rename") }
func (r *recorder) Remove(name string) error       { return r.step("remove " + filepath.Base(name)) }
func (r *recorder) SyncDir(string) error           { return r.step("fsync-dir") }
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
