package orchestrator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

// cleanupDaemon answers the image list, image removal, build cache prune
// and info requests of the auto-cleanup (V1 G1).
type cleanupDaemon struct {
	mu       sync.Mutex
	images   []image.Summary
	status   map[string]int // DELETE /images/<id> reply status; 200 when absent
	removed  []string
	queries  []string
	rootDir  string
	failInfo bool
}

func (d *cleanupDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = append(d.queries, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	w.Header().Set("Content-Type", "application/json")
	reply := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	p := r.URL.Path
	switch {
	case p == "/_ping":
		w.Header().Set("Api-Version", "1.56")
		_, _ = io.WriteString(w, "OK")
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/images/json"):
		reply(http.StatusOK, d.images)
	case r.Method == http.MethodDelete && strings.Contains(p, "/images/"):
		id := p[strings.Index(p, "/images/")+len("/images/"):]
		if st, ok := d.status[id]; ok {
			reply(st, map[string]string{"message": "refused"})
			return
		}
		d.removed = append(d.removed, id)
		reply(http.StatusOK, []image.DeleteResponse{{Deleted: id}})
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/build/prune"):
		reply(http.StatusOK, map[string]any{"CachesDeleted": []string{"a", "b"}, "SpaceReclaimed": 4096})
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/info"):
		if d.failInfo {
			reply(http.StatusInternalServerError, map[string]string{"message": "daemon busy"})
			return
		}
		reply(http.StatusOK, map[string]any{"DockerRootDir": d.rootDir})
	default:
		http.NotFound(w, r)
	}
}

func cleanupEngine(t *testing.T, d *cleanupDaemon, dataRoot string, stat DiskStat) *DockerEngine {
	t.Helper()
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	cli, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithAPIVersion("1.56"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return &DockerEngine{client: cli, proxyContainer: "traefik-proxy", limits: testLimits, dataRoot: dataRoot, statDisk: stat}
}

func builtImage(id, env, job string, size int64, tags ...string) image.Summary {
	labels := map[string]string{LabelEnv: env}
	if job != "" {
		labels[LabelJob] = job
	}
	return image.Summary{ID: id, Labels: labels, RepoTags: tags, Size: size}
}

// prunableImages selects only images previewd built (both ownership
// labels, valid), tagged at most <env>:latest, of environments not kept.
func TestPrunableImages(t *testing.T) {
	images := []image.Summary{
		builtImage("sha256:gone", testEnv, "3", 10, testEnv+":latest"),
		builtImage("sha256:untagged", testEnv, "2", 20),
		builtImage("sha256:dangling", testEnv, "1", 30, "<none>:<none>"),
		builtImage("sha256:kept", otherEnv, "4", 40, otherEnv+":latest"),
		builtImage("sha256:nojob", testEnv, "", 50),
		builtImage("sha256:badjob", testEnv, "0", 50),
		builtImage("sha256:badenv", "Not_An_Env", "5", 50),
		builtImage("sha256:operator", testEnv, "6", 50, "registry.local/base:1"),
		builtImage("sha256:retagged", testEnv, "7", 50, testEnv+":latest", "busybox:latest"),
		builtImage("sha256:foreign", otherEnv, "8", 50, testEnv+":latest"),
	}
	var got []string
	for _, img := range prunableImages(images, []string{otherEnv}) {
		got = append(got, img.ID)
	}
	if want := []string{"sha256:gone", "sha256:untagged", "sha256:dangling"}; !slices.Equal(got, want) {
		t.Fatalf("prunable = %v, want %v", got, want)
	}
}

// PruneImages lists by the ownership label, removes without force, skips
// an image in use (409) or gone (404), and reports any other failure.
func TestDockerPruneImages(t *testing.T) {
	d := &cleanupDaemon{
		images: []image.Summary{
			builtImage("sha256:a", testEnv, "1", 100, testEnv+":latest"),
			builtImage("sha256:inuse", testEnv, "2", 200),
			builtImage("sha256:gone", testEnv, "3", 300),
			builtImage("sha256:kept", otherEnv, "4", 400, otherEnv+":latest"),
		},
		status: map[string]int{"sha256:inuse": http.StatusConflict, "sha256:gone": http.StatusNotFound},
	}
	e := cleanupEngine(t, d, "", nil)
	reclaimed, err := e.PruneImages(t.Context(), []string{otherEnv})
	if err != nil || reclaimed != 100 || !slices.Equal(d.removed, []string{"sha256:a"}) {
		t.Fatalf("PruneImages = %d, %v; removed %v", reclaimed, err, d.removed)
	}
	for _, q := range d.queries {
		switch {
		case strings.HasPrefix(q, "GET ") && strings.Contains(q, "/images/json"):
			if !strings.Contains(q, "previewd.env") {
				t.Errorf("image list %q not filtered by the ownership label", q)
			}
		case strings.HasPrefix(q, "DELETE "):
			if strings.Contains(q, "force=1") || strings.Contains(q, "noprune=1") {
				t.Errorf("image removal %q is forced or keeps its parents", q)
			}
		}
	}

	d.status["sha256:a"] = http.StatusInternalServerError
	d.removed = nil
	if _, err := e.PruneImages(t.Context(), []string{otherEnv}); err == nil {
		t.Fatal("a failed removal was not reported")
	}
}

func TestDockerPruneBuildCache(t *testing.T) {
	d := &cleanupDaemon{}
	e := cleanupEngine(t, d, "", nil)
	reclaimed, err := e.PruneBuildCache(t.Context())
	if err != nil || reclaimed != 4096 {
		t.Fatalf("PruneBuildCache = %d, %v", reclaimed, err)
	}
	if q := d.queries[len(d.queries)-1]; !strings.Contains(q, "/build/prune") || !strings.Contains(q, "all=1") {
		t.Fatalf("prune request %q, want all unused cache", q)
	}
}

// FreeDisk measures PREVIEWD_DOCKER_DATA_ROOT, or the daemon's data root.
// Fail closed: an unreadable root, a daemon that cannot say, a root that is
// not a clean absolute path, or no probe gives no size.
func TestDockerFreeDisk(t *testing.T) {
	var asked []string
	stat := func(path string) (int64, error) {
		asked = append(asked, path)
		if path == "/unreadable" {
			return 0, errors.New("permission denied")
		}
		return 7 << 30, nil
	}
	d := &cleanupDaemon{rootDir: "/var/lib/docker/100000.100000"}
	if free, err := cleanupEngine(t, d, "/srv/docker", stat).FreeDisk(t.Context()); err != nil || free != 7<<30 {
		t.Fatalf("FreeDisk(configured) = %d, %v", free, err)
	}
	if free, err := cleanupEngine(t, d, "", stat).FreeDisk(t.Context()); err != nil || free != 7<<30 {
		t.Fatalf("FreeDisk(daemon root) = %d, %v", free, err)
	}
	if want := []string{"/srv/docker", "/var/lib/docker/100000.100000"}; !slices.Equal(asked, want) {
		t.Fatalf("measured %v, want %v", asked, want)
	}
	for name, e := range map[string]*DockerEngine{
		"unreadable":    cleanupEngine(t, &cleanupDaemon{}, "/unreadable", stat),
		"info fails":    cleanupEngine(t, &cleanupDaemon{failInfo: true}, "", stat),
		"relative root": cleanupEngine(t, &cleanupDaemon{rootDir: "docker"}, "", stat),
		"unclean root":  cleanupEngine(t, &cleanupDaemon{rootDir: "/var/lib/../lib/docker"}, "", stat),
		"empty root":    cleanupEngine(t, &cleanupDaemon{}, "", stat),
		"no probe":      cleanupEngine(t, &cleanupDaemon{}, "/srv/docker", nil),
	} {
		if free, err := e.FreeDisk(t.Context()); err == nil {
			t.Errorf("%s: FreeDisk = %d, nil; want an error", name, free)
		}
	}
}

func TestNewDockerEngineRefusesDataRoot(t *testing.T) {
	stat := func(string) (int64, error) { return 0, nil }
	for _, root := range []string{"relative", "/var/lib/docker/", "/var/lib/../lib/docker"} {
		if _, err := NewDockerEngine("traefik-proxy", testLimits, root, stat); err == nil {
			t.Errorf("data root %q accepted", root)
		}
	}
	if _, err := NewDockerEngine("traefik-proxy", testLimits, "/var/lib/docker", nil); err == nil {
		t.Error("no free-disk probe accepted")
	}
}
