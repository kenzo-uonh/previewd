package orchestrator

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
)

const (
	pgImageID    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	redisImageID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// composeDaemon is a Docker daemon holding the resources of environments. It
// records every request as "METHOD path" in order, answers the calls the
// compose lifecycle makes, and holds the containers, volumes and network
// created through it.
type composeDaemon struct {
	mu         sync.Mutex
	log        []string
	images     map[string]image.InspectResponse // by the name:tag inspected
	containers map[string]container.Summary     // by name
	creates    map[string]createBody            // by container name, as sent
	volumes    map[string]volume.Volume
	volCreates []volume.CreateRequest
	networks   map[string]network.Summary
	// foreignVolume makes /volumes/create answer with a volume another owner
	// made: the daemon returns the existing volume of that name.
	foreignVolume *volume.Volume
}

// createBody is the /containers/create request: the container config sits at
// the top level, beside HostConfig and NetworkingConfig.
type createBody struct {
	container.Config
	HostConfig       container.HostConfig     `json:"HostConfig"`
	NetworkingConfig network.NetworkingConfig `json:"NetworkingConfig"`
}

func newComposeDaemon() *composeDaemon {
	return &composeDaemon{
		images: map[string]image.InspectResponse{
			"docker.io/library/postgres:16": {ID: pgImageID, RepoDigests: []string{"postgres@sha256:" + strings.Repeat("1", 64)}},
			"docker.io/library/redis:7":     {ID: redisImageID, RepoDigests: []string{"redis@sha256:" + strings.Repeat("2", 64)}},
		},
		containers: map[string]container.Summary{},
		creates:    map[string]createBody{},
		volumes:    map[string]volume.Volume{},
		networks:   map[string]network.Summary{},
	}
}

func (d *composeDaemon) record(r *http.Request) {
	d.log = append(d.log, r.Method+" "+r.URL.Path)
}

// index is the position of the first request of the log that has all of the
// fragments, or -1.
func (d *composeDaemon) index(fragments ...string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.IndexFunc(d.log, func(l string) bool {
		for _, f := range fragments {
			if !strings.Contains(l, f) {
				return false
			}
		}
		return true
	})
}

func (d *composeDaemon) saw(fragments ...string) bool { return d.index(fragments...) >= 0 }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *composeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(r)
	// The versioned prefix (/v1.56) is not part of the route.
	p := r.URL.Path
	if i := strings.Index(p, "/containers/"); i >= 0 {
		p = p[i:]
	} else if i := strings.Index(p, "/volumes"); i >= 0 {
		p = p[i:]
	} else if i := strings.Index(p, "/networks"); i >= 0 {
		p = p[i:]
	} else if i := strings.Index(p, "/images/"); i >= 0 {
		p = p[i:]
	}
	notFound := func() { writeJSON(w, http.StatusNotFound, map[string]string{"message": "No such object"}) }
	// matches applies the label filter of the request: "key=value", or "key"
	// for any value.
	matches := func(labels map[string]string) bool {
		var f map[string]map[string]bool
		_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &f)
		for want := range f["label"] {
			k, val, hasVal := strings.Cut(want, "=")
			if v, ok := labels[k]; !ok || (hasVal && v != val) {
				return false
			}
		}
		return true
	}
	switch {
	case r.URL.Path == "/_ping":
		w.Header().Set("Api-Version", "1.56")
		_, _ = io.WriteString(w, "OK")

	case r.Method == http.MethodGet && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		ref, _ := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json"))
		img, ok := d.images[ref]
		if !ok {
			notFound()
			return
		}
		writeJSON(w, http.StatusOK, img)

	case r.Method == http.MethodPost && p == "/volumes/create":
		var req volume.CreateRequest
		_ = json.Unmarshal(body, &req)
		d.volCreates = append(d.volCreates, req)
		if d.foreignVolume != nil {
			writeJSON(w, http.StatusCreated, *d.foreignVolume)
			return
		}
		v := volume.Volume{Name: req.Name, Driver: "local", Labels: req.Labels, Mountpoint: "/var/lib/docker/volumes/" + req.Name}
		d.volumes[req.Name] = v
		writeJSON(w, http.StatusCreated, v)
	case r.Method == http.MethodGet && p == "/volumes":
		var items []volume.Volume
		for _, v := range d.volumes {
			if matches(v.Labels) {
				items = append(items, v)
			}
		}
		writeJSON(w, http.StatusOK, volume.ListResponse{Volumes: items})
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/volumes/"):
		name := strings.TrimPrefix(p, "/volumes/")
		if _, ok := d.volumes[name]; !ok {
			notFound()
			return
		}
		delete(d.volumes, name)
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && p == "/containers/create":
		var req createBody
		_ = json.Unmarshal(body, &req)
		name := r.URL.Query().Get("name")
		d.creates[name] = req
		d.containers[name] = container.Summary{
			ID: "id-" + name, Names: []string{"/" + name}, State: container.StateCreated, Labels: req.Labels,
		}
		writeJSON(w, http.StatusCreated, container.CreateResponse{ID: "id-" + name})
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/start"):
		name := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/id-"), "/start")
		c, ok := d.containers[name]
		if !ok {
			notFound()
			return
		}
		c.State = container.StateRunning
		d.containers[name] = c
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && p == "/containers/json":
		var items []container.Summary
		for _, c := range d.containers {
			if matches(c.Labels) {
				items = append(items, c)
			}
		}
		writeJSON(w, http.StatusOK, items)
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/json") && strings.HasPrefix(p, "/containers/"):
		name := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")
		name = strings.TrimPrefix(name, "id-")
		if name == "traefik-proxy" {
			res := cleanProxy()
			res.Name = "/traefik-proxy"
			writeJSON(w, http.StatusOK, res)
			return
		}
		c, ok := d.containers[name]
		if !ok {
			notFound()
			return
		}
		writeJSON(w, http.StatusOK, container.InspectResponse{
			ID: c.ID, Name: "/" + name, State: &container.State{Running: c.State == container.StateRunning},
			NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{
				name + "-net":      nil,
				networkOf(d, name): {IPAddress: netip.MustParseAddr("172.31.0.2")},
			}},
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/containers/"):
		name := strings.TrimPrefix(strings.TrimPrefix(p, "/containers/"), "id-")
		if _, ok := d.containers[name]; !ok {
			notFound()
			return
		}
		delete(d.containers, name)
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && p == "/networks":
		var items []network.Summary
		for _, n := range d.networks {
			items = append(items, n)
		}
		writeJSON(w, http.StatusOK, items)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/connect"):
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/disconnect"):
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/networks/"):
		name := strings.TrimPrefix(p, "/networks/")
		if _, ok := d.networks[name]; !ok {
			notFound()
			return
		}
		delete(d.networks, name)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/images/"):
		writeJSON(w, http.StatusOK, []image.DeleteResponse{})
	default:
		http.NotFound(w, r)
	}
}

// networkOf is the environment network a container of the daemon sits on.
func networkOf(d *composeDaemon, name string) string {
	return d.creates[name].HostConfig.NetworkMode.NetworkName()
}

func composeEngine(t *testing.T, d *composeDaemon) *DockerEngine {
	t.Helper()
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	cli, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithAPIVersion("1.56"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return &DockerEngine{client: cli, proxyContainer: "traefik-proxy", limits: testLimits}
}

func testComposeEnv(t *testing.T) Environment {
	t.Helper()
	spec, err := ParseCompose([]byte(composeThree), testSidecarImages, 3)
	if err != nil {
		t.Fatal(err)
	}
	return Environment{ID: testEnv, Image: testEnv + ":latest", Port: 8080, Domain: "local.previewd", JobID: 5, SecretsDir: "/run/previewd-secrets/" + testEnv, Compose: spec}
}

func TestDeployComposeStartsSidecarsBeforeThePrimaryOnTheEnvironmentNetwork(t *testing.T) {
	d := newComposeDaemon()
	eng := composeEngine(t, d)
	env := testComposeEnv(t)

	addr, err := eng.Deploy(t.Context(), env)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("172.31.0.2:8080"); addr != want {
		t.Errorf("backend = %s, want the primary's address %s", addr, want)
	}

	net := networkName(env.ID)
	names := []string{env.ID + "-postgres", env.ID + "-redis", env.ID}
	for _, n := range names {
		c, ok := d.creates[n]
		if !ok {
			t.Fatalf("container %s was not created (created: %v)", n, slices.Sorted(mapKeys(d.creates)))
		}
		if got := c.HostConfig.NetworkMode.NetworkName(); got != net {
			t.Errorf("%s network mode = %q, want only %q", n, got, net)
		}
		if c.Labels[LabelEnv] != env.ID || c.Labels[LabelJob] != "5" {
			t.Errorf("%s labels = %v, want the ownership labels of %s", n, c.Labels, env.ID)
		}
		if len(c.HostConfig.PortBindings) != 0 || c.HostConfig.PublishAllPorts || len(c.ExposedPorts) != 0 {
			t.Errorf("%s publishes or exposes a port: bindings %v, publish-all %v, exposed %v",
				n, c.HostConfig.PortBindings, c.HostConfig.PublishAllPorts, c.ExposedPorts)
		}
		if !slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) || !slices.Contains(c.HostConfig.SecurityOpt, "no-new-privileges:true") ||
			c.HostConfig.Privileged || !c.HostConfig.ReadonlyRootfs {
			t.Errorf("%s is not hardened: caps %v, security %v, privileged %v, read-only %v",
				n, c.HostConfig.CapDrop, c.HostConfig.SecurityOpt, c.HostConfig.Privileged, c.HostConfig.ReadonlyRootfs)
		}
		if c.HostConfig.Memory != testLimits.MemoryBytes || c.HostConfig.MemorySwap != testLimits.MemoryBytes ||
			c.HostConfig.PidsLimit == nil || *c.HostConfig.PidsLimit != testLimits.Pids {
			t.Errorf("%s is not bounded by the container limits", n)
		}
		if got := slices.Collect(mapKeys(c.NetworkingConfig.EndpointsConfig)); !slices.Equal(got, []string{net}) {
			t.Errorf("%s endpoints = %v, want only %s", n, got, net)
		}
	}

	pg := d.creates[env.ID+"-postgres"]
	if pg.Image != pgImageID {
		t.Errorf("postgres runs %q, want the image ID of the verified local image %s", pg.Image, pgImageID)
	}
	if got := pg.NetworkingConfig.EndpointsConfig[net].Aliases; !slices.Equal(got, []string{"postgres"}) {
		t.Errorf("postgres aliases = %v, want its service name", got)
	}
	if !slices.Contains(pg.Env, "POSTGRES_PASSWORD=pw") {
		t.Errorf("postgres env = %v, want the compose environment", pg.Env)
	}
	wantVol := "previewd-" + env.ID + "-pgdata"
	if !slices.ContainsFunc(pg.HostConfig.Mounts, func(m mount.Mount) bool {
		return m.Type == mount.TypeVolume && m.Source == wantVol && m.Target == "/var/lib/postgresql/data" && !m.ReadOnly
	}) {
		t.Errorf("postgres mounts = %+v, want the named volume %s", pg.HostConfig.Mounts, wantVol)
	}
	rd := d.creates[env.ID+"-redis"]
	if !slices.Equal(rd.Cmd, []string{"redis-server", "--save", ""}) {
		t.Errorf("redis command = %v", rd.Cmd)
	}

	// Only the primary gets the secrets mount, read-only, and its own image.
	for _, n := range names[:2] {
		for _, m := range d.creates[n].HostConfig.Mounts {
			if m.Type == mount.TypeBind || m.Target == SecretsMountTarget {
				t.Errorf("sidecar %s mounts %+v: only the primary receives the secrets", n, m)
			}
		}
	}
	primary := d.creates[env.ID]
	if primary.Image != env.Image {
		t.Errorf("primary runs %q, want the build %q", primary.Image, env.Image)
	}
	if !slices.ContainsFunc(primary.HostConfig.Mounts, func(m mount.Mount) bool {
		return m.Type == mount.TypeBind && m.Source == env.SecretsDir && m.Target == SecretsMountTarget && m.ReadOnly
	}) {
		t.Errorf("primary mounts = %+v, want the read-only secrets bind", primary.HostConfig.Mounts)
	}
	if !slices.Contains(primary.Env, "DATABASE_URL=postgres://app:pw@postgres:5432/app") {
		t.Errorf("primary env = %v, want the compose environment", primary.Env)
	}

	// Order: images verified and the volume created before any container;
	// every sidecar started before the primary is created.
	pgStart, rdStart := d.index("POST", "id-"+env.ID+"-postgres/start"), d.index("POST", "id-"+env.ID+"-redis/start")
	firstCreate := d.index("containers/create")
	if v := d.index("volumes/create"); v < 0 || v > firstCreate {
		t.Errorf("volume created at %d, after the first container at %d", v, firstCreate)
	}
	if pgStart < 0 || rdStart < 0 {
		t.Fatalf("sidecars not started: %v", d.log)
	}
	creates := 0
	for i, l := range d.log {
		if strings.Contains(l, "containers/create") {
			creates++
			if creates == 3 && (i < pgStart || i < rdStart) {
				t.Errorf("the primary was created before every sidecar started: %v", d.log)
			}
		}
	}
	if d.saw("images/create") {
		t.Errorf("an image was pulled: %v", d.log)
	}
	if !d.saw("/networks/"+net+"/connect") && !d.saw("/connect") {
		t.Errorf("the proxy was not joined to the environment network: %v", d.log)
	}
}

func TestDeployComposeCreatesVolumesScopedAndLabelled(t *testing.T) {
	d := newComposeDaemon()
	env := testComposeEnv(t)
	if _, err := composeEngine(t, d).Deploy(t.Context(), env); err != nil {
		t.Fatal(err)
	}
	if len(d.volCreates) != 1 {
		t.Fatalf("volumes created = %+v, want exactly the one the compose file mounts", d.volCreates)
	}
	v := d.volCreates[0]
	if v.Name != "previewd-"+env.ID+"-pgdata" {
		t.Errorf("volume name = %q, want previewd-<env>-pgdata", v.Name)
	}
	if v.Labels[LabelEnv] != env.ID || v.Labels[LabelJob] != "5" {
		t.Errorf("volume labels = %v, want the ownership labels", v.Labels)
	}
	if v.Driver != "local" || len(v.DriverOpts) != 0 {
		t.Errorf("volume driver %q options %v: want the plain local driver", v.Driver, v.DriverOpts)
	}
}

// A volume of that name that another owner made, or with options, is never
// reused: it could be a bind mount of a host path.
func TestDeployComposeRefusesAForeignVolume(t *testing.T) {
	env := testComposeEnv(t)
	name := "previewd-" + env.ID + "-pgdata"
	for label, v := range map[string]volume.Volume{
		"no ownership label": {Name: name, Driver: "local", Mountpoint: "/x"},
		"another owner":      {Name: name, Driver: "local", Labels: map[string]string{LabelEnv: "pr-9-ffffffffff"}},
		"driver options":     {Name: name, Driver: "local", Labels: map[string]string{LabelEnv: env.ID}, Options: map[string]string{"o": "bind", "device": "/etc"}},
		"another driver":     {Name: name, Driver: "nfs", Labels: map[string]string{LabelEnv: env.ID}},
	} {
		t.Run(label, func(t *testing.T) {
			d := newComposeDaemon()
			d.foreignVolume = &v
			if _, err := composeEngine(t, d).Deploy(t.Context(), env); err == nil {
				t.Fatal("Deploy accepted the volume")
			}
			if d.saw("containers/create") {
				t.Errorf("a container was created after the volume was refused: %v", d.log)
			}
		})
	}
}

// Fail closed: a sidecar image that is not on the host, or is another image
// under the pinned name:tag, stops the deploy before any volume or container,
// and nothing is pulled.
func TestDeployComposeFailsClosedOnSidecarImages(t *testing.T) {
	tests := map[string]func(d *composeDaemon){
		"missing locally": func(d *composeDaemon) { delete(d.images, "docker.io/library/redis:7") },
		"another digest": func(d *composeDaemon) {
			d.images["docker.io/library/redis:7"] = image.InspectResponse{ID: "sha256:" + strings.Repeat("9", 64)}
		},
		"onbuild trigger": func(d *composeDaemon) {
			img := d.images["docker.io/library/redis:7"]
			img.Config = &dockerspec.DockerOCIImageConfig{}
			img.Config.OnBuild = []string{"RUN curl evil"}
			d.images["docker.io/library/redis:7"] = img
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			d := newComposeDaemon()
			mutate(d)
			if _, err := composeEngine(t, d).Deploy(t.Context(), testComposeEnv(t)); err == nil {
				t.Fatal("Deploy accepted the sidecar image")
			}
			for _, frag := range []string{"volumes/create", "containers/create", "images/create"} {
				if d.saw(frag) {
					t.Errorf("%s reached the daemon before the images were verified: %v", frag, d.log)
				}
			}
		})
	}
}

func TestDeployWithoutComposeIsUnchanged(t *testing.T) {
	d := newComposeDaemon()
	env := testComposeEnv(t)
	env.Compose = nil
	if _, err := composeEngine(t, d).Deploy(t.Context(), env); err != nil {
		t.Fatal(err)
	}
	if len(d.creates) != 1 || d.saw("volumes/create") {
		t.Errorf("a plain deploy created %d containers and volumes %v", len(d.creates), d.volCreates)
	}
	primary := d.creates[env.ID]
	if len(primary.Env) != 0 || len(primary.HostConfig.Mounts) != 1 {
		t.Errorf("plain primary env %v mounts %+v: want no env and the secrets mount only", primary.Env, primary.HostConfig.Mounts)
	}
}

// seed puts the resources of env on the daemon: the primary, two sidecars,
// the network and a volume, plus a bystander environment.
func (d *composeDaemon) seed(env string) {
	lab := map[string]string{LabelEnv: env, LabelJob: "5"}
	for _, n := range []string{env, env + "-postgres", env + "-redis"} {
		d.containers[n] = container.Summary{ID: "id-" + n, Names: []string{"/" + n}, State: container.StateRunning, Labels: lab}
	}
	d.networks[networkName(env)] = network.Summary{Name: networkName(env), Labels: map[string]string{LabelEnv: env}}
	d.volumes["previewd-"+env+"-pgdata"] = volume.Volume{Name: "previewd-" + env + "-pgdata", Driver: "local", Labels: lab}
}

func TestDestroyRemovesEverySidecarNetworkAndVolume(t *testing.T) {
	d := newComposeDaemon()
	d.seed(testEnv)
	const other = "pr-8-0b0b0b0b0b"
	d.seed(other)
	if err := composeEngine(t, d).Destroy(t.Context(), testEnv); err != nil {
		t.Fatal(err)
	}
	for n := range d.containers {
		if strings.HasPrefix(n, testEnv) {
			t.Errorf("container %s survived Destroy", n)
		}
	}
	if _, ok := d.networks[networkName(testEnv)]; ok {
		t.Error("the environment network survived Destroy")
	}
	if len(d.volumes) != 1 {
		t.Errorf("volumes after Destroy = %v, want only the other environment's", d.volumes)
	}
	if _, ok := d.volumes["previewd-"+other+"-pgdata"]; !ok {
		t.Error("Destroy removed another environment's volume")
	}
	if len(d.containers) != 3 || len(d.networks) != 1 {
		t.Errorf("Destroy touched another environment: containers %d, networks %d", len(d.containers), len(d.networks))
	}
	// Containers go before the network, the network before the volumes: a
	// volume or a network in use cannot be removed.
	lastContainer := -1
	for i, l := range d.log {
		if strings.HasPrefix(l, "DELETE") && strings.Contains(l, "/containers/") {
			lastContainer = i
		}
	}
	if net, vol := d.index("DELETE", "/networks/"), d.index("DELETE", "/volumes/"); lastContainer >= net || net >= vol {
		t.Errorf("teardown order wrong (last container %d, network %d, volume %d): %v", lastContainer, net, vol, d.log)
	}
}

// A crash between the volume and the first container leaves a volume and
// nothing else: Destroy still removes it, and Observe reports it.
func TestDestroyRemovesAnOrphanedVolume(t *testing.T) {
	d := newComposeDaemon()
	d.volumes["previewd-"+testEnv+"-pgdata"] = volume.Volume{Name: "previewd-" + testEnv + "-pgdata", Driver: "local", Labels: map[string]string{LabelEnv: testEnv}}
	eng := composeEngine(t, d)
	states, err := eng.Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := states[testEnv]; !ok || st.Volumes != 1 || st.Running || st.Containers != 0 {
		t.Fatalf("Observe = %+v, want %s with one volume and no container", states, testEnv)
	}
	if err := eng.Destroy(t.Context(), testEnv); err != nil {
		t.Fatal(err)
	}
	if len(d.volumes) != 0 {
		t.Errorf("volumes after Destroy = %v", d.volumes)
	}
}

func TestObserveCountsSidecarsAndVolumes(t *testing.T) {
	d := newComposeDaemon()
	d.seed(testEnv)
	states, err := composeEngine(t, d).Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := EngineState{Running: true, NetworkBound: true, Containers: 3, Volumes: 1, JobID: 5}
	if states[testEnv] != want {
		t.Errorf("Observe = %+v, want %+v", states[testEnv], want)
	}
}

// A running sidecar does not make a dead primary look alive: Running is the
// primary's.
func TestObserveRunningIsThePrimary(t *testing.T) {
	d := newComposeDaemon()
	d.seed(testEnv)
	c := d.containers[testEnv]
	c.State = container.StateExited
	d.containers[testEnv] = c
	states, err := composeEngine(t, d).Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if states[testEnv].Running {
		t.Errorf("Observe = %+v, want Running false: only a sidecar runs", states[testEnv])
	}
}

func TestSidecarSpecHardening(t *testing.T) {
	env := testComposeEnv(t)
	cfg, host, err := sidecarSpec(env, env.Compose.Sidecars[0], pgImageID, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Image != pgImageID || host.NetworkMode != container.NetworkMode(networkName(env.ID)) {
		t.Errorf("image %q network %q", cfg.Image, host.NetworkMode)
	}
	if host.Privileged || host.PidMode != "" || host.IpcMode != "" || host.UsernsMode != "" || host.UTSMode != "" ||
		len(host.Binds) != 0 || len(host.Devices) != 0 || len(host.PortBindings) != 0 || host.PublishAllPorts {
		t.Errorf("sidecar host config reaches the host: %+v", host)
	}
	if !slices.Equal(host.CapDrop, []string{"ALL"}) {
		t.Errorf("CapDrop = %v", host.CapDrop)
	}
	// Only what an official database image's entrypoint needs to drop to its
	// own user and own its data directory.
	want := []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
	if got := slices.Sorted(slices.Values(host.CapAdd)); !slices.Equal(got, want) {
		t.Errorf("CapAdd = %v, want %v", got, want)
	}
	for _, m := range host.Mounts {
		switch m.Type {
		case mount.TypeBind:
			t.Errorf("sidecar has a bind mount %+v", m)
		case mount.TypeTmpfs:
			if m.TmpfsOptions == nil || m.TmpfsOptions.SizeBytes <= 0 {
				t.Errorf("unbounded tmpfs %+v", m)
			}
		}
	}
}

func TestSidecarSpecRefusesWithoutAnImage(t *testing.T) {
	env := testComposeEnv(t)
	if _, _, err := sidecarSpec(env, env.Compose.Sidecars[0], "", testLimits); err == nil {
		t.Error("a sidecar without a resolved image was accepted")
	}
	if _, _, err := sidecarSpec(Environment{ID: "bad", Compose: env.Compose}, env.Compose.Sidecars[0], pgImageID, testLimits); err == nil {
		t.Error("a sidecar of an invalid environment ID was accepted")
	}
}

func mapKeys[M ~map[K]V, K comparable, V any](m M) func(yield func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
