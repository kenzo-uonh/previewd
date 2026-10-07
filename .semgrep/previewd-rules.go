// Fixture for `semgrep --test .semgrep/`. Never compiled: directories whose
// name starts with "." are outside the Go module's package set.

package fixture

import (
	"context"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func envLiteral(secret string) *container.Config {
	// ruleid: previewd-no-container-env
	return &container.Config{Image: "app", Env: []string{"TOKEN=" + secret}}
}

func envAssign(cfg *container.Config, secret string) {
	// ruleid: previewd-no-container-env
	cfg.Env = []string{"TOKEN=" + secret}
}

func envAbsent() *container.Config {
	// ok: previewd-no-container-env
	return &container.Config{Image: "app"}
}

func secretMounts() []mount.Mount {
	return []mount.Mount{
		// ruleid: previewd-secret-mount-memory-backed
		{Type: mount.TypeVolume, Source: "env-secrets", Target: "/run/secrets"},
		// ruleid: previewd-secret-bind-readonly
		mount.Mount{Type: mount.TypeBind, Source: "/run/previewd/secrets/env", Target: "/run/secrets"},
		// ok: previewd-secret-bind-readonly
		mount.Mount{Type: mount.TypeBind, Source: "/run/previewd/secrets/env", Target: "/run/secrets", ReadOnly: true},
		// ok: previewd-secret-mount-memory-backed
		mount.Mount{Type: mount.TypeTmpfs, Target: "/run/secrets"},
		// ruleid: previewd-secret-mount-memory-backed
		mount.Mount{Type: mount.TypeVolume, Source: "env-secrets", Target: "/run/secrets"},
		// ok: previewd-secret-mount-memory-backed
		mount.Mount{Type: mount.TypeVolume, Source: "cache", Target: "/var/cache/app"},
		// ruleid: previewd-secret-bind-readonly
		{Type: mount.TypeBind, Source: "/run/previewd/secrets/env", Target: "/run/secrets"},
		// ok: previewd-secret-bind-readonly
		{Type: mount.TypeBind, Source: "/run/previewd/secrets/env", Target: "/run/secrets", ReadOnly: true},
		// ok: previewd-secret-mount-memory-backed
		{Type: mount.TypeTmpfs, Target: "/run/secrets"},
	}
}

func binds() *container.HostConfig {
	return &container.HostConfig{
		Binds: []string{
			// ruleid: previewd-secret-binds-readonly
			"/run/previewd/secrets/env:/run/secrets",
			// ok: previewd-secret-binds-readonly
			"/run/previewd/secrets/env:/run/secrets:ro",
		},
	}
}

func rootContext() {
	// ruleid: previewd-no-root-context
	ctx := context.Background()
	_ = ctx
}

func derivedContext(ctx context.Context) {
	// ok: previewd-no-root-context
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = cctx
}
