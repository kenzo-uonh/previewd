package orchestrator

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/store"
)

// composeRig is a rig whose checkout carries a compose file and whose
// allowlist holds the sidecar images.
func composeRig(t *testing.T, file string) *rig {
	t.Helper()
	r := newRig(t)
	r.composeFile = file
	r.composeEnabled = true
	r.bases = maps.Clone(testSidecarImages)
	return r
}

func (r *rig) deployOnce() []store.Job {
	r.t.Helper()
	rec := r.reconciler()
	if err := rec.Startup(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	r.enqueue(store.JobDeploy)
	return r.drain(rec)
}

func TestRunDeployPassesTheComposeSpecToTheEngine(t *testing.T) {
	r := composeRig(t, composeThree)
	if jobs := r.deployOnce(); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("jobs = %+v, want SUCCESS", jobs)
	}
	if len(r.engine.deployed) != 1 {
		t.Fatalf("deploys = %d, want 1", len(r.engine.deployed))
	}
	spec := r.engine.deployed[0].Compose
	if spec == nil || spec.Primary.Name != "app" || len(spec.Sidecars) != 2 {
		t.Fatalf("Deploy received compose spec %+v, want app with two sidecars", spec)
	}
	// The compose file is validated after the Dockerfile preflight and before
	// the first request that changes the host.
	if want := []string{"observe", "destroy", "network"}; !slices.Equal(r.engine.calls[:3], want) {
		t.Errorf("engine calls = %v, want the usual order", r.engine.calls)
	}
}

func TestRunDeployFallsBackToDockerCompose(t *testing.T) {
	r := composeRig(t, composeThree)
	r.composeName = composeFallbackName
	if jobs := r.deployOnce(); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("jobs = %+v, want SUCCESS", jobs)
	}
	if r.engine.deployed[0].Compose == nil {
		t.Error("docker-compose.yml was not read")
	}
}

// Off by default: a compose file in the PR changes nothing.
func TestRunDeployIgnoresComposeWhenDisabled(t *testing.T) {
	r := composeRig(t, composeThree)
	r.composeEnabled = false
	if jobs := r.deployOnce(); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("jobs = %+v, want SUCCESS", jobs)
	}
	if r.engine.deployed[0].Compose != nil {
		t.Error("a compose file was used with PREVIEWD_COMPOSE_ENABLED off")
	}
}

func TestRunDeployWithoutAComposeFileIsUnchanged(t *testing.T) {
	r := composeRig(t, "")
	if jobs := r.deployOnce(); lastStatus(jobs) != store.StatusSuccess {
		t.Fatalf("jobs = %+v, want SUCCESS", jobs)
	}
	if r.engine.deployed[0].Compose != nil {
		t.Error("a compose spec appeared without a compose file")
	}
}

// Fail closed: a compose file that is refused fails the deploy at the
// preflight step; no network, build or container reaches the engine.
func TestRunDeployRefusesAnInvalidComposeFileBeforeTheEngine(t *testing.T) {
	bind := strings.Replace(composeThree, "pgdata:/var/lib/postgresql/data", "/var/lib/data:/var/lib/postgresql/data", 1)
	tooMany := strings.Replace(composeThree, "services:\n", "services:\n  extra:\n    image: redis:7@sha256:"+strings.Repeat("2", 64)+"\n", 1)
	notAllowed := strings.Replace(composeThree, "postgres:16@", "postgres:17@", 1)
	for name, file := range map[string]string{"host bind mount": bind, "four services": tooMany, "image not allowlisted": notAllowed} {
		t.Run(name, func(t *testing.T) {
			r := composeRig(t, file)
			jobs := r.deployOnce()
			if lastStatus(jobs) != store.StatusFailed {
				t.Fatalf("jobs = %+v, want FAILED", jobs)
			}
			if got := jobs[len(jobs)-1].Failure; got != store.FailurePreflight {
				t.Errorf("failure = %q, want %q", got, store.FailurePreflight)
			}
			for _, call := range []string{"network", "build", "deploy"} {
				if slices.Contains(r.engine.calls, call) {
					t.Errorf("engine calls %q: a refused compose file reached the engine", r.engine.calls)
				}
			}
		})
	}
}

func TestNewReconcilerComposeServiceBound(t *testing.T) {
	r := newRig(t)
	for name, tc := range map[string]struct {
		on  bool
		max int
		ok  bool
	}{
		"off, default":   {false, 0, true},
		"on, default":    {true, 0, true},
		"on, explicit":   {true, 5, true},
		"on, at ceiling": {true, maxComposeServices, true},
		"on, above":      {true, maxComposeServices + 1, false},
		"negative":       {true, -1, false},
		"negative, off":  {false, -1, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := r.config()
			cfg.ComposeEnabled, cfg.ComposeMaxServices = tc.on, tc.max
			cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
			_, err := NewReconciler(cfg)
			if (err == nil) != tc.ok {
				t.Errorf("NewReconciler = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
