package proxy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kenzo-uonh/previewd/internal/envid"
)

// routeFileMode lets the Traefik container, which runs as another user and
// mounts the routes directory read-only, read route documents.
const routeFileMode fs.FileMode = 0o644

// Publisher writes one route document per environment into the directory
// Traefik's file provider watches.
type Publisher struct {
	dir string
	fs  fileOps
}

// NewPublisher returns a Publisher for dir, which must be an existing,
// absolute directory (symlinks refused).
func NewPublisher(dir string) (*Publisher, error) {
	return newPublisher(dir, osOps{})
}

func newPublisher(dir string, ops fileOps) (*Publisher, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("routes dir %q must be an absolute path", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat routes dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("routes dir %q is not a directory (symlinks refused)", dir)
	}
	return &Publisher{dir: filepath.Clean(dir), fs: ops}, nil
}

// RouteFile is the file name of envID's route document. Traefik's file
// provider loads *.yml; temporary files never match.
func RouteFile(envID string) string {
	return envID + ".yml"
}

// Publish renders r and replaces its route document atomically: Traefik
// sees either the previous document or the new one, never a partial write,
// and the new one survives a crash once Publish returns.
func (p *Publisher) Publish(r Route) error {
	doc, err := Render(r)
	if err != nil {
		return err
	}
	if err := writeAtomic(p.fs, p.dir, RouteFile(r.EnvID), doc); err != nil {
		return fmt.Errorf("publish route %s: %w", r.EnvID, err)
	}
	return nil
}

// Remove deletes envID's route document durably. It is idempotent.
func (p *Publisher) Remove(envID string) error {
	if !envid.Valid(envID) {
		return fmt.Errorf("remove route: invalid environment id %q", envID)
	}
	if err := p.fs.Remove(filepath.Join(p.dir, RouteFile(envID))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove route %s: %w", envID, err)
	}
	if err := p.fs.SyncDir(p.dir); err != nil {
		return fmt.Errorf("remove route %s: %w", envID, err)
	}
	return nil
}

// Inventory returns the environment IDs that have a route document, after
// removing every other file Traefik's file provider could load: temporary
// files left by an interrupted Publish, and any .yml, .yaml or .toml file
// that is not a route document of a valid environment (a foreign file in the
// watched directory is a route injection). removed lists what was deleted.
// A directory, symlink or other non-regular entry refuses the inventory:
// previewd writes none, and Traefik may follow it.
func (p *Publisher) Inventory() (routes, removed []string, err error) {
	entries, err := p.fs.ReadDir(p.dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read routes dir: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			return nil, nil, fmt.Errorf("routes dir: %q is not a regular file: refusing to start until it is removed", name)
		}
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		switch {
		case ext == ".yml" && !strings.HasPrefix(name, ".") && envid.Valid(stem):
			routes = append(routes, stem)
			continue
		case strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-"):
		case ext == ".yml" || ext == ".yaml" || ext == ".toml":
		default:
			continue // Traefik ignores it
		}
		if err := p.fs.Remove(filepath.Join(p.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("remove %s from routes dir: %w", name, err)
		}
		removed = append(removed, name)
	}
	if len(removed) > 0 {
		if err := p.fs.SyncDir(p.dir); err != nil {
			return nil, nil, fmt.Errorf("routes dir: %w", err)
		}
	}
	return routes, removed, nil
}

// writeAtomic: write a temporary file in dir, fsync it, rename it over
// name, then fsync dir so the rename itself is durable.
func writeAtomic(ops fileOps, dir, name string, data []byte) (err error) {
	tmp, err := ops.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if renamed {
			return
		}
		if closeErr := tmp.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			err = errors.Join(err, fmt.Errorf("close temporary file: %w", closeErr))
		}
		if rmErr := ops.Remove(tmpName); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary file: %w", rmErr))
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Chmod(routeFileMode); err != nil {
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := ops.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	renamed = true
	if err := ops.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync routes dir: %w", err)
	}
	return nil
}

type tempFile interface {
	Name() string
	Write(b []byte) (int, error)
	Chmod(mode fs.FileMode) error
	Sync() error
	Close() error
}

type fileOps interface {
	ReadDir(dir string) ([]fs.DirEntry, error)
	CreateTemp(dir, pattern string) (tempFile, error)
	Rename(oldpath, newpath string) error
	Remove(name string) error
	SyncDir(dir string) error
}

type osOps struct{}

func (osOps) ReadDir(dir string) ([]fs.DirEntry, error)        { return os.ReadDir(dir) }
func (osOps) CreateTemp(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) }
func (osOps) Rename(oldpath, newpath string) error             { return os.Rename(oldpath, newpath) }
func (osOps) Remove(name string) error                         { return os.Remove(name) }

func (osOps) SyncDir(dir string) (err error) {
	d, err := os.Open(dir) // #nosec G304 -- the publisher's own routes directory, validated at construction
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close dir: %w", closeErr))
		}
	}()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}
