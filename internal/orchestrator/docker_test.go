package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/mount"
)

func TestContainerSpecMountsSecretsReadOnlyWithoutEnv(t *testing.T) {
	env := Environment{ID: "pr-7", Image: "pr-7:latest", Port: 8080, Domain: "local.previewd", SecretsDir: "/run/previewd/secrets/pr-7"}

	cfg, hostCfg, err := containerSpec(env)
	if err != nil {
		t.Fatalf("containerSpec: %v", err)
	}
	if len(cfg.Env) != 0 {
		t.Fatalf("container env must be empty, got %q", cfg.Env)
	}
	if len(hostCfg.Binds) != 0 {
		t.Fatalf("legacy Binds must be unused, got %q", hostCfg.Binds)
	}
	if len(hostCfg.Mounts) != 1 {
		t.Fatalf("want exactly one mount, got %+v", hostCfg.Mounts)
	}

	m := hostCfg.Mounts[0]
	if m.Type != mount.TypeBind || m.Source != env.SecretsDir || m.Target != SecretsMountTarget {
		t.Fatalf("secrets mount = %+v, want bind %s -> %s", m, env.SecretsDir, SecretsMountTarget)
	}
	if !m.ReadOnly {
		t.Fatal("secrets mount must be read-only")
	}
	if m.BindOptions == nil || m.BindOptions.Propagation != mount.PropagationRPrivate || !m.BindOptions.NonRecursive {
		t.Fatalf("secrets mount bind options = %+v, want rprivate, non-recursive", m.BindOptions)
	}
}

func TestContainerSpecFailsClosedWithoutStagedDir(t *testing.T) {
	for _, dir := range []string{"", "relative/pr-7", "pr-7"} {
		env := Environment{ID: "pr-7", Image: "pr-7:latest", SecretsDir: dir}
		if _, _, err := containerSpec(env); err == nil {
			t.Errorf("containerSpec accepted secrets dir %q", dir)
		}
	}
}

type fakeEngine struct {
	Engine
	destroyErr error
	calls      *[]string
}

func (f fakeEngine) Destroy(context.Context, string) error {
	*f.calls = append(*f.calls, "destroy")
	return f.destroyErr
}

type fakeStager struct {
	removeErr error
	calls     *[]string
}

func (f fakeStager) Stage(string, map[string]string) (string, error) { return "", nil }

func (f fakeStager) Remove(string) error {
	*f.calls = append(*f.calls, "remove")
	return f.removeErr
}

func TestTeardownRemovesSecretsAfterContainerEvenOnDestroyFailure(t *testing.T) {
	destroyErr := errors.New("daemon down")
	removeErr := errors.New("busy")

	cases := []struct {
		name              string
		destroyErr, rmErr error
		wantErrs          []error
	}{
		{"both succeed", nil, nil, nil},
		{"destroy fails", destroyErr, nil, []error{destroyErr}},
		{"remove fails", nil, removeErr, []error{removeErr}},
		{"both fail", destroyErr, removeErr, []error{destroyErr, removeErr}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			err := Teardown(context.Background(),
				fakeEngine{destroyErr: tc.destroyErr, calls: &calls},
				fakeStager{removeErr: tc.rmErr, calls: &calls},
				"pr-7")

			if len(calls) != 2 || calls[0] != "destroy" || calls[1] != "remove" {
				t.Fatalf("calls = %v, want [destroy remove]", calls)
			}
			if len(tc.wantErrs) == 0 && err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			for _, want := range tc.wantErrs {
				if !errors.Is(err, want) {
					t.Fatalf("Teardown error %v does not wrap %v", err, want)
				}
			}
		})
	}
}
