package orchestrator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

// fakeDaemon records the requests of a DockerEngine and answers /build
// with a recorded response stream, HTTP 200 whatever the stream says.
type fakeDaemon struct {
	mu       sync.Mutex
	stream   []byte
	images   map[string]image.InspectResponse // by the reference inspected
	bridge   string                           // GET /networks/bridge reply
	requests []*http.Request
	bodies   [][]byte
}

func (f *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.bodies = append(f.bodies, body)
	f.mu.Unlock()
	switch p := r.URL.Path; {
	case p == "/_ping":
		w.Header().Set("Api-Version", "1.56")
		_, _ = io.WriteString(w, "OK")
	case r.Method == http.MethodDelete && strings.Contains(p, "/images/"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "[]")
	case strings.HasSuffix(p, "/networks/bridge"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, f.bridge)
	case strings.HasSuffix(p, "/build"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.stream)
	case strings.Contains(p, "/images/") && strings.HasSuffix(p, "/json"):
		ref, err := url.PathUnescape(strings.TrimSuffix(p[strings.Index(p, "/images/")+len("/images/"):], "/json"))
		img, ok := f.images[ref]
		if err != nil || !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"No such image"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(img)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeDaemon) builds() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var idx []int
	for i, r := range f.requests {
		if strings.HasSuffix(r.URL.Path, "/build") {
			idx = append(idx, i)
		}
	}
	return idx
}

func newFakeEngine(t *testing.T, f *fakeDaemon) *DockerEngine {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cli, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithAPIVersion("1.56"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return &DockerEngine{client: cli, proxyContainer: "traefik-proxy", limits: testLimits}
}

func recordedStream(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "buildstream", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The /build request is exactly D-V1-2: BuildKit, networkmode none, no
// pull, no cache, intermediate containers removed even on failure, the
// ownership labels; no build argument, session, remote context, platform,
// target, output, credential, or per-build limit (D-V1-4). The body is the
// tar previewd validated, byte for byte.
func TestBuildRequestIsLockedDown(t *testing.T) {
	f := &fakeDaemon{stream: recordedStream(t, "buildkit-ok.jsonl")}
	e := newFakeEngine(t, f)
	tarball := []byte("validated context tar")
	err := e.Build(context.Background(), BuildSpec{ContextTar: bytes.NewReader(tarball), Tag: testEnv + ":latest", EnvID: testEnv, JobID: 42})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	idx := f.builds()
	if len(idx) != 1 {
		t.Fatalf("%d build requests, want 1", len(idx))
	}
	r, body := f.requests[idx[0]], f.bodies[idx[0]]
	if r.Method != http.MethodPost {
		t.Fatalf("method %s", r.Method)
	}
	assertLockedQuery(t, r.URL.Query(), testEnv+":latest", `{"previewd.env":"`+testEnv+`","previewd.job":"42"}`)
	if ct := r.Header.Get("Content-Type"); ct != "application/x-tar" {
		t.Errorf("Content-Type %q", ct)
	}
	reg, err := base64.URLEncoding.DecodeString(r.Header.Get("X-Registry-Config"))
	if err != nil || (string(reg) != "null" && string(reg) != "{}") {
		t.Errorf("X-Registry-Config = %q, %v: no registry credential may be sent", reg, err)
	}
	if !bytes.Equal(body, tarball) {
		t.Errorf("body = %q, want the validated tar", body)
	}
}

// assertLockedQuery: exactly the D-V1-2 build parameters, with tag and
// labels, and none of the parameters previewd must never send.
func assertLockedQuery(t *testing.T, got url.Values, tag, labels string) {
	t.Helper()
	want := url.Values{
		"version":     {"2"},
		"networkmode": {"none"},
		"nocache":     {"1"},
		"forcerm":     {"1"},
		"dockerfile":  {"Dockerfile"},
		"t":           {tag},
		"labels":      {labels},
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected build parameter %s=%q", k, got[k])
		}
	}
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Errorf("build parameter %s = %q, want %q", k, got[k], v)
		}
	}
	// rm is the daemon's default (true) and pull its default (false): the
	// client sends them only to change them.
	for _, k := range []string{"rm", "pull", "memory", "memswap", "cpuquota", "cpuperiod", "cpushares", "cgroupparent", "buildargs", "session", "remote"} {
		if got.Has(k) {
			t.Errorf("build parameter %s must not be sent, got %q", k, got[k])
		}
	}
}

// The MVP defect: the daemon answers 200 and reports the failure in the
// stream. Every recorded failure fails Build.
func TestBuildFailsOnAnErrorInTheStream(t *testing.T) {
	for _, name := range []string{"buildkit-run-fails.jsonl", "buildkit-parse-error.jsonl", "classic-run-fails.jsonl"} {
		t.Run(name, func(t *testing.T) {
			e := newFakeEngine(t, &fakeDaemon{stream: recordedStream(t, name)})
			err := e.Build(context.Background(), BuildSpec{ContextTar: strings.NewReader("x"), Tag: testEnv + ":latest", EnvID: testEnv, JobID: 1})
			if !errors.Is(err, ErrBuildFailed) {
				t.Fatalf("Build = %v, want ErrBuildFailed", err)
			}
		})
	}
	t.Run("error after success", func(t *testing.T) {
		stream := append(recordedStream(t, "buildkit-ok.jsonl"), []byte(`{"errorDetail":{"message":"export failed"},"error":"export failed"}`+"\r\n")...)
		e := newFakeEngine(t, &fakeDaemon{stream: stream})
		err := e.Build(context.Background(), BuildSpec{ContextTar: strings.NewReader("x"), Tag: testEnv + ":latest", EnvID: testEnv, JobID: 1})
		if !errors.Is(err, ErrBuildFailed) {
			t.Fatalf("Build = %v, want ErrBuildFailed", err)
		}
	})
}

// An invalid spec sends nothing.
func TestBuildRefusesAnInvalidSpecWithoutARequest(t *testing.T) {
	ok := BuildSpec{ContextTar: strings.NewReader("x"), Tag: testEnv + ":latest", EnvID: testEnv, JobID: 1}
	for name, mutate := range map[string]func(*BuildSpec){
		"invalid env":     func(s *BuildSpec) { s.EnvID, s.Tag = "../x", "../x:latest" },
		"foreign tag":     func(s *BuildSpec) { s.Tag = "busybox:latest" },
		"tag of another":  func(s *BuildSpec) { s.Tag = "pr-8-0a0a0a0a0a:latest" },
		"job 0":           func(s *BuildSpec) { s.JobID = 0 },
		"no context":      func(s *BuildSpec) { s.ContextTar = nil },
		"negative job ID": func(s *BuildSpec) { s.JobID = -3 },
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeDaemon{stream: recordedStream(t, "buildkit-ok.jsonl")}
			e := newFakeEngine(t, f)
			spec := ok
			mutate(&spec)
			if err := e.Build(context.Background(), spec); err == nil {
				t.Fatal("invalid spec accepted")
			}
			if n := len(f.builds()); n != 0 {
				t.Fatalf("%d build requests sent for an invalid spec", n)
			}
		})
	}
}

const testBaseDigest = "sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"

func TestVerifyBaseImages(t *testing.T) {
	const local = "docker.io/library/busybox:latest" // the record the daemon falls back to
	other := "sha256:" + strings.Repeat("1", 64)
	onbuild := &dockerspec.DockerOCIImageConfig{}
	onbuild.OnBuild = []string{"ADD https://example.invalid/x /x"}
	for name, tc := range map[string]struct {
		images map[string]image.InspectResponse
		ok     bool
	}{
		"repository digest": {map[string]image.InspectResponse{local: {ID: other, RepoDigests: []string{"busybox@" + testBaseDigest}}}, true},
		"ID is the digest":  {map[string]image.InspectResponse{local: {ID: testBaseDigest}}, true},
		"not loaded":        {map[string]image.InspectResponse{}, false},
		"tag points elsewhere": {map[string]image.InspectResponse{local: {
			ID: other, RepoDigests: []string{"busybox@" + other},
		}}, false},
		"digest under another name": {map[string]image.InspectResponse{local: {
			ID: other, RepoDigests: []string{"alpine@" + testBaseDigest},
		}}, false},
		"onbuild": {map[string]image.InspectResponse{local: {ID: testBaseDigest, Config: onbuild}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newFakeEngine(t, &fakeDaemon{images: tc.images})
			err := e.VerifyBaseImages(context.Background(), testBases)
			if (err == nil) != tc.ok {
				t.Fatalf("VerifyBaseImages = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	t.Run("empty allowlist", func(t *testing.T) {
		e := newFakeEngine(t, &fakeDaemon{})
		if err := e.VerifyBaseImages(context.Background(), map[string]bool{}); err == nil {
			t.Fatal("empty allowlist accepted")
		}
	})
}
