//go:build e2e

// Package dockerapi checks the auto-cleanup of the Docker engine (V1 spec G1)
// against the real daemon, as scripts/verify-e2e.sh runs it: images built
// with previewd's own locked-down /build request, FROM scratch so nothing is
// pulled. A test tool behind the e2e build tag.
package dockerapi

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/hardening"
	"github.com/kenzo-uonh/previewd/internal/orchestrator"
)

// Environments of this test only: PR numbers no E2E scenario uses.
const (
	envKept   = "pr-424241-0e2e0e2e0e"
	envGone   = "pr-424242-0e2e0e2e0e"
	envInUse  = "pr-424243-0e2e0e2e0e"
	operator  = "previewd-e2e-operator:keep"
	container = "previewd-e2e-in-use"
)

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput() // #nosec G204 -- test tool, fixed arguments
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func imageExists(ref string) bool {
	return exec.Command("docker", "image", "inspect", ref).Run() == nil // #nosec G204 -- test tool
}

// buildContext is a tar holding a Dockerfile FROM scratch and one file.
func buildContext(t *testing.T, env string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range map[string]string{"Dockerfile": "FROM scratch\nCOPY hello /hello\n", "hello": env + "\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestDockerCleanupAgainstTheEngine(t *testing.T) {
	ctx := context.Background()
	eng, err := orchestrator.NewDockerEngine("traefik-proxy", orchestrator.Limits{MemoryBytes: 64 << 20, Pids: 64},
		os.Getenv("E2E_DOCKER_DATA_ROOT"), hardening.FreeDiskBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", container).Run()                                                           // #nosec G204 -- test tool
		_ = exec.Command("docker", "rmi", "-f", operator, envKept+":latest", envGone+":latest", envInUse+":latest").Run() // #nosec G204 -- test tool
		_ = eng.Close()
	})
	if err := eng.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	// FreeDisk: the statfs of the daemon's data root, as hardening reads it.
	free, err := eng.FreeDisk(ctx)
	if err != nil || free <= 0 {
		t.Fatalf("FreeDisk = %d, %v", free, err)
	}
	root := docker(t, "info", "-f", "{{.DockerRootDir}}")
	direct, err := hardening.FreeDiskBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if diff := free - direct; diff > 1<<30 || diff < -(1<<30) {
		t.Fatalf("FreeDisk = %d, statfs of %s = %d", free, root, direct)
	}
	t.Logf("FreeDisk: %d MiB free on %s", free>>20, root)

	for i, env := range []string{envKept, envGone, envInUse} {
		if err := eng.Build(ctx, orchestrator.BuildSpec{ContextTar: buildContext(t, env), Tag: env + ":latest", EnvID: env, JobID: int64(i + 1)}); err != nil {
			t.Fatalf("build %s: %v", env, err)
		}
	}
	// An image a container uses, and an operator's tag on a previewd image.
	docker(t, "create", "--name", container, "--network", "none", envInUse+":latest", "/hello")
	docker(t, "tag", envKept+":latest", operator)

	reclaimed, err := eng.PruneImages(ctx, []string{envKept})
	if err != nil {
		t.Fatalf("PruneImages(keep %s) = %v", envKept, err)
	}
	switch {
	case imageExists(envGone + ":latest"):
		t.Fatalf("%s survived the prune", envGone)
	case !imageExists(envKept+":latest") || !imageExists(operator):
		t.Fatal("the kept environment's image was removed")
	case !imageExists(envInUse + ":latest"):
		t.Fatal("an image a container uses was removed")
	}
	t.Logf("PruneImages: %d bytes reclaimed", reclaimed)

	// Nothing kept: the image carrying an operator's tag and the one in use
	// stay; once untagged and unused, they go.
	if _, err := eng.PruneImages(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !imageExists(operator) || !imageExists(envInUse+":latest") {
		t.Fatal("PruneImages removed an operator's image or one in use")
	}
	docker(t, "rmi", operator)
	docker(t, "rm", container)
	if _, err := eng.PruneImages(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if imageExists(envKept+":latest") || imageExists(envInUse+":latest") {
		t.Fatal("previewd images survived a prune that keeps nothing")
	}

	// PruneBuildCache: whatever the builds above left goes; a second prune
	// finds nothing.
	first, err := eng.PruneBuildCache(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := eng.PruneBuildCache(ctx); err != nil || again != 0 {
		t.Fatalf("second PruneBuildCache = %d, %v; want nothing left", again, err)
	}
	t.Logf("PruneBuildCache: %d bytes reclaimed", first)
}
