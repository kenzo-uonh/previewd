package orchestrator

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	testPostgres = "docker.io/library/postgres:16@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testRedis    = "docker.io/library/redis:7@sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

var testSidecarImages = map[string]bool{testPostgres: true, testRedis: true, testBase: true}

// composeThree is the reference manifest: the application plus PostgreSQL
// and Redis.
const composeThree = `
services:
  app:
    build: .
    environment:
      DATABASE_URL: postgres://app:pw@postgres:5432/app
      CACHE_HOST: redis
    depends_on: [postgres, redis]
  postgres:
    image: postgres:16@sha256:1111111111111111111111111111111111111111111111111111111111111111
    environment:
      - POSTGRES_USER=app
      - POSTGRES_PASSWORD=pw
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports: ["5432:5432"]
    expose: ["5432"]
  redis:
    image: redis:7@sha256:2222222222222222222222222222222222222222222222222222222222222222
    command: ["redis-server", "--save", ""]
    ports:
      - "6379:6379"
volumes:
  pgdata:
`

func TestParseComposeAcceptsAppWithSidecars(t *testing.T) {
	spec, err := ParseCompose([]byte(composeThree), testSidecarImages, 3)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Primary.Name != "app" || spec.Primary.Image != "" {
		t.Errorf("primary = %+v, want the service with build, no image", spec.Primary)
	}
	if want := []string{"CACHE_HOST=redis", "DATABASE_URL=postgres://app:pw@postgres:5432/app"}; !slices.Equal(spec.Primary.Env, want) {
		t.Errorf("primary env = %v, want %v", spec.Primary.Env, want)
	}
	if len(spec.Sidecars) != 2 || spec.Sidecars[0].Name != "postgres" || spec.Sidecars[1].Name != "redis" {
		t.Fatalf("sidecars = %+v, want postgres then redis", spec.Sidecars)
	}
	pg, rd := spec.Sidecars[0], spec.Sidecars[1]
	if pg.Image != testPostgres || rd.Image != testRedis {
		t.Errorf("images = %q, %q, want the canonical allowlisted references", pg.Image, rd.Image)
	}
	if want := []string{"POSTGRES_PASSWORD=pw", "POSTGRES_USER=app"}; !slices.Equal(pg.Env, want) {
		t.Errorf("postgres env = %v, want %v", pg.Env, want)
	}
	if want := []ComposeMount{{Volume: "pgdata", Target: "/var/lib/postgresql/data"}}; !slices.Equal(pg.Mounts, want) {
		t.Errorf("postgres mounts = %+v, want %+v", pg.Mounts, want)
	}
	if want := []string{"redis-server", "--save", ""}; !slices.Equal(rd.Command, want) {
		t.Errorf("redis command = %v, want %v", rd.Command, want)
	}
	if want := []string{"pgdata"}; !slices.Equal(spec.Volumes, want) {
		t.Errorf("volumes = %v, want %v", spec.Volumes, want)
	}
}

// Sidecar ports are never published: ports and expose are counted and
// dropped, whatever they say.
func TestParseComposeStripsPortsAndExpose(t *testing.T) {
	spec, err := ParseCompose([]byte(composeThree), testSidecarImages, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.Sidecars[0].IgnoredPorts; got != 2 {
		t.Errorf("postgres ignored ports = %d, want 2 (ports + expose)", got)
	}
	if got := spec.Sidecars[1].IgnoredPorts; got != 1 {
		t.Errorf("redis ignored ports = %d, want 1", got)
	}
}

func TestParseComposeLongVolumeSyntaxAndReadOnly(t *testing.T) {
	doc := `
services:
  app: {build: .}
  postgres:
    image: postgres:16@sha256:1111111111111111111111111111111111111111111111111111111111111111
    volumes:
      - {type: volume, source: pgdata, target: /var/lib/postgresql/data}
      - pgconf:/etc/pg:ro
volumes: {pgdata: {}, pgconf: null}
`
	spec, err := ParseCompose([]byte(doc), testSidecarImages, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []ComposeMount{
		{Volume: "pgdata", Target: "/var/lib/postgresql/data"},
		{Volume: "pgconf", Target: "/etc/pg", ReadOnly: true},
	}
	if !slices.Equal(spec.Sidecars[0].Mounts, want) {
		t.Errorf("mounts = %+v, want %+v", spec.Sidecars[0].Mounts, want)
	}
}

func TestParseComposeServiceCountBound(t *testing.T) {
	if _, err := ParseCompose([]byte(composeThree), testSidecarImages, 3); err != nil {
		t.Fatalf("three services at a bound of 3: %v", err)
	}
	_, err := ParseCompose([]byte(composeThree), testSidecarImages, 2)
	if !errors.Is(err, ErrCompose) || !strings.Contains(err.Error(), "3 services") {
		t.Errorf("three services at a bound of 2: %v, want ErrCompose naming the count", err)
	}
	four := composeThree + "\n"
	four = strings.Replace(four, "services:\n", "services:\n  extra:\n    image: redis:7@sha256:2222222222222222222222222222222222222222222222222222222222222222\n", 1)
	if _, err := ParseCompose([]byte(four), testSidecarImages, 3); !errors.Is(err, ErrCompose) {
		t.Errorf("four services at a bound of 3: %v, want ErrCompose", err)
	}
}

// Every refusal is ErrCompose, before the engine is reached.
func TestParseComposeFailsClosed(t *testing.T) {
	const pg = "image: postgres:16@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	svc := func(extra string) string {
		return "services:\n  app: {build: .}\n  postgres:\n    " + pg + "\n" + extra + "\nvolumes:\n  pgdata:\n"
	}
	appWith := func(extra string) string {
		return "services:\n  app:\n    build: .\n" + extra + "\n  postgres:\n    " + pg + "\nvolumes:\n  pgdata:\n"
	}
	tests := map[string]struct{ doc, want string }{
		"bind mount, absolute host path": {svc("    volumes: ['/var/lib/data:/data']"), "host bind mount"},
		"bind mount, relative ./":        {svc("    volumes: ['./data:/data']"), "host bind mount"},
		"bind mount, relative ../":       {svc("    volumes: ['../data:/data']"), "host bind mount"},
		"bind mount, home":               {svc("    volumes: ['~/data:/data']"), "host bind mount"},
		"bind mount, nested relative":    {svc("    volumes: ['data/sub:/data']"), "host bind mount"},
		"bind mount, long syntax":        {svc("    volumes:\n      - {type: bind, source: /etc, target: /data}"), "host bind mount"},
		"tmpfs mount, long syntax":       {svc("    volumes:\n      - {type: tmpfs, target: /data}"), "type"},
		"anonymous volume":               {svc("    volumes: ['/data']"), "anonymous"},
		"undeclared named volume":        {svc("    volumes: ['other:/data']"), "not declared"},
		"mount mode other than ro or rw": {svc("    volumes: ['pgdata:/data:z']"), "mode"},
		"mount over the secrets mount":   {svc("    volumes: ['pgdata:/run/secrets']"), "target"},
		"relative mount target":          {svc("    volumes: ['pgdata:data']"), "target"},
		"unclean mount target":           {svc("    volumes: ['pgdata:/data/../etc']"), "target"},
		"privileged":                     {svc("    privileged: true"), "privileged"},
		"privileged false still refused": {svc("    privileged: false"), "privileged"},
		"network_mode host":              {svc("    network_mode: host"), "network_mode"},
		"pid host":                       {svc("    pid: host"), "pid"},
		"ipc host":                       {svc("    ipc: host"), "ipc"},
		"cap_add":                        {svc("    cap_add: [SYS_ADMIN]"), "cap_add"},
		"devices":                        {svc("    devices: ['/dev/sda:/dev/sda']"), "devices"},
		"security_opt":                   {svc("    security_opt: ['seccomp=unconfined']"), "security_opt"},
		"env_file reads the host":        {svc("    env_file: /etc/shadow"), "env_file"},
		"volumes_from":                   {svc("    volumes_from: [app]"), "volumes_from"},
		"unsupported key fails closed":   {svc("    healthcheck: {test: [CMD, true]}"), "healthcheck"},
		"user":                           {svc("    user: root"), "user"},
		"entrypoint":                     {svc("    entrypoint: [/bin/sh]"), "entrypoint"},
		"string command":                 {svc("    command: redis-server --save"), "command"},
		"inherited env, list item":       {svc("    environment: [HOME]"), "environment"},
		"inherited env, null value":      {svc("    environment: {HOME: }"), "environment"},
		"env interpolation":              {svc("    environment: {PW: '${DB_PASSWORD}'}"), "interpolation"},
		"env key with a space":           {svc("    environment: {'A B': x}"), "environment"},
		"depends_on unknown service":     {svc("    depends_on: [ghost]"), "depends_on"},
		"image not allowlisted":          {strings.Replace(svc(""), "postgres:16@sha256:1111111111111111111111111111111111111111111111111111111111111111", "postgres:17@sha256:1111111111111111111111111111111111111111111111111111111111111111", 1), "allowed"},
		"image not pinned":               {strings.Replace(svc(""), "@sha256:1111111111111111111111111111111111111111111111111111111111111111", "", 1), "pinned"},
		"sidecar without image":          {"services:\n  app: {build: .}\n  db: {}\n", "image"},
		"sidecar with build":             {"services:\n  app: {build: .}\n  db: {build: ./db}\n", "build"},
		"two build services":             {"services:\n  app: {build: .}\n  worker: {build: .}\n", "build"},
		"no build service":               {"services:\n  postgres:\n    " + pg + "\n", "build"},
		"no services":                    {"services: {}\n", "service"},
		"build with another dockerfile":  {appWith("    build: {context: ., dockerfile: Other}"), "build"},
		"build context outside the root": {appWith("    build: ../elsewhere"), "build"},
		"build with args":                {appWith("    build: {context: ., args: {A: b}}"), "build"},
		"invalid service name":           {"services:\n  App_1: {build: .}\n", "service name"},
		"top-level volume with options":  {"services:\n  app: {build: .}\nvolumes:\n  v: {driver: local, driver_opts: {type: none, o: bind, device: /etc}}\n", "volumes"},
		"top-level external volume":      {"services:\n  app: {build: .}\nvolumes:\n  v: {external: true}\n", "volumes"},
		"top-level networks":             {"services:\n  app: {build: .}\nnetworks: {n: {}}\n", "networks"},
		"top-level secrets":              {"services:\n  app: {build: .}\nsecrets: {s: {file: /etc/shadow}}\n", "secrets"},
		"two documents":                  {"services:\n  app: {build: .}\n---\nservices: {}\n", "document"},
		"not yaml":                       {"services: [unterminated", "parse"},
		"not a mapping":                  {"- a\n- b\n", "parse"},
		"duplicate keys":                 {"services:\n  app: {build: .}\n  app: {build: .}\n", "parse"},
		"oversized document":             {"services:\n  app: {build: .}\n# " + strings.Repeat("x", maxComposeBytes), "bytes"},
		"too many environment variables": {appWith("    environment:\n" + strings.Repeat("      - A=1\n", 65)), "environment"},
		"environment value too long":     {appWith("    environment: {A: '" + strings.Repeat("x", 5000) + "'}"), "environment"},
		"alias bomb":                     {"a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\ng: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\nh: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\ni: [*h,*h,*h,*h,*h,*h,*h,*h,*h]\nservices: {app: {build: .}}\n", ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCompose([]byte(tc.doc), testSidecarImages, 3)
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if !errors.Is(err, ErrCompose) {
				t.Errorf("error %v is not ErrCompose", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseComposeRefusesUnboundedMaxServices(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := ParseCompose([]byte(composeThree), testSidecarImages, n); err == nil {
			t.Errorf("service bound %d accepted", n)
		}
	}
}

func TestLoadCompose(t *testing.T) {
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	t.Run("none", func(t *testing.T) {
		data, name, err := LoadCompose(write(t, map[string]string{"Dockerfile": "x"}))
		if err != nil || data != nil || name != "" {
			t.Errorf("got %q, %q, %v; want nothing", data, name, err)
		}
	})
	t.Run("previewd file wins", func(t *testing.T) {
		data, name, err := LoadCompose(write(t, map[string]string{composeFileName: "a", composeFallbackName: "b"}))
		if err != nil || string(data) != "a" || name != composeFileName {
			t.Errorf("got %q, %q, %v; want a from %s", data, name, err, composeFileName)
		}
	})
	t.Run("fallback", func(t *testing.T) {
		data, name, err := LoadCompose(write(t, map[string]string{composeFallbackName: "b"}))
		if err != nil || string(data) != "b" || name != composeFallbackName {
			t.Errorf("got %q, %q, %v; want b from %s", data, name, err, composeFallbackName)
		}
	})
	t.Run("symlink is refused", func(t *testing.T) {
		dir := write(t, map[string]string{"real": "a"})
		if err := os.Symlink("real", filepath.Join(dir, composeFileName)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadCompose(dir); !errors.Is(err, ErrCompose) {
			t.Errorf("symlinked compose file: %v, want ErrCompose", err)
		}
	})
	t.Run("directory is refused", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, composeFileName), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadCompose(dir); !errors.Is(err, ErrCompose) {
			t.Errorf("compose file is a directory: %v, want ErrCompose", err)
		}
	})
	t.Run("oversize is refused, never truncated", func(t *testing.T) {
		dir := write(t, map[string]string{composeFileName: strings.Repeat("x", maxComposeBytes+1)})
		if _, _, err := LoadCompose(dir); !errors.Is(err, ErrCompose) {
			t.Errorf("oversized compose file: %v, want ErrCompose", err)
		}
	})
}
