package orchestrator

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/kenzo-uonh/previewd/internal/validate"
	"gopkg.in/yaml.v3"
)

// The compose parser (V1.1 phase 4) turns the compose file of a PR into the
// sidecars of its environment. It accepts a small, explicit subset of the
// format and refuses everything else: a key it does not list is a refusal,
// never an ignored setting. Every refusal happens before any request reaches
// the engine.
//
// What a compose file can ask for is bounded by construction:
//   - one service builds (the primary, previewd's root Dockerfile, built with
//     the locked request of every PR build); every other service runs an
//     image of PREVIEWD_ALLOWED_BASE_IMAGES, which previewd never pulls;
//   - at most PREVIEWD_COMPOSE_MAX_SERVICES services in all;
//   - storage is named volumes only, declared at the top level without any
//     option (a driver option can turn a named volume into a host bind
//     mount): no host path, no tmpfs, no anonymous volume;
//   - no published or exposed port (ports and expose are counted and dropped:
//     the environment network is internal and only the proxy reaches the
//     primary);
//   - no privilege, host namespace, device, capability or security option, no
//     env_file (it would read a host file), no networks and no secrets.

// ErrCompose is a compose file refused before any request reaches the engine.
var ErrCompose = errors.New("compose file refused")

const (
	// composeFileName is the compose file previewd reads first, composeFallbackName
	// the one it reads when the first is absent.
	composeFileName     = "previewd.compose.yml"
	composeFallbackName = "docker-compose.yml"
	// maxComposeBytes bounds the compose file read from the PR.
	maxComposeBytes = 256 << 10
	// DefaultComposeServices and maxComposeServices are the default and the
	// ceiling of PREVIEWD_COMPOSE_MAX_SERVICES, the services of one
	// environment, primary included (internal/config holds the same values: it
	// cannot import this package).
	defaultComposeServices = 3
	maxComposeServices     = 8
	// Bounds on what one service may set.
	maxComposeEnv      = 64
	maxComposeEnvBytes = 4096
	maxComposeCommand  = 64
	maxComposeMounts   = 8
)

// ComposeSpec is a validated compose file: the service that runs the PR's
// build, the sidecars, and the named volumes the services mount. It carries
// no port, no host path and no secret.
type ComposeSpec struct {
	Primary  ComposeService
	Sidecars []ComposeService // sorted by name
	Volumes  []string         // volumes mounted by at least one service, sorted
}

// ComposeService is one validated service.
type ComposeService struct {
	Name string
	// Image is the canonical, allowlisted reference of a sidecar
	// (validate.BaseImage); empty for the primary, which runs the build.
	Image   string
	Env     []string // sorted KEY=value
	Command []string
	Mounts  []ComposeMount
	// IgnoredPorts counts the ports and expose entries that were dropped.
	IgnoredPorts int
}

// ComposeMount mounts the environment's volume Volume at Target.
type ComposeMount struct {
	Volume   string
	Target   string
	ReadOnly bool
}

func composeRefusef(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCompose}, args...)...)
}

// composeDoc is the top level of a compose file. Rest catches every key the
// parser does not model.
type composeDoc struct {
	Version  any                  `yaml:"version"`
	Name     any                  `yaml:"name"`
	Services map[string]rawSvc    `yaml:"services"`
	Volumes  map[string]yaml.Node `yaml:"volumes"`
	Rest     map[string]any       `yaml:",inline"`
}

// rawSvc is one service as written. A key outside this list lands in Rest.
type rawSvc struct {
	Build       yaml.Node            `yaml:"build"`
	Image       string               `yaml:"image"`
	Environment yaml.Node            `yaml:"environment"`
	Command     yaml.Node            `yaml:"command"`
	Volumes     yaml.Node            `yaml:"volumes"`
	Ports       yaml.Node            `yaml:"ports"`
	Expose      yaml.Node            `yaml:"expose"`
	DependsOn   yaml.Node            `yaml:"depends_on"`
	Restart     any                  `yaml:"restart"`
	Rest        map[string]yaml.Node `yaml:",inline"`
}

// ParseCompose validates a compose file. allowedImages holds canonical
// references (validate.AllowedBaseImages); maxServices is
// PREVIEWD_COMPOSE_MAX_SERVICES. Every refusal wraps ErrCompose.
func ParseCompose(data []byte, allowedImages map[string]bool, maxServices int) (*ComposeSpec, error) {
	if maxServices <= 0 {
		return nil, fmt.Errorf("compose: the service bound must be positive, got %d", maxServices)
	}
	if len(data) > maxComposeBytes {
		return nil, composeRefusef("compose file is %d bytes, above the %d-byte cap", len(data), maxComposeBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc composeDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, composeRefusef("parse compose file: %s", q(err.Error()))
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, composeRefusef("the compose file holds more than one YAML document")
	}
	for _, key := range slices.Sorted(maps.Keys(doc.Rest)) {
		return nil, composeRefusef("top-level key %s is not supported (previewd owns networks, secrets and configs)", q(key))
	}
	switch n := len(doc.Services); {
	case n == 0:
		return nil, composeRefusef("the compose file defines no service")
	case n > maxServices:
		return nil, composeRefusef("%d services, above PREVIEWD_COMPOSE_MAX_SERVICES (%d)", n, maxServices)
	}
	declared, err := declaredVolumes(doc.Volumes)
	if err != nil {
		return nil, err
	}

	names := slices.Sorted(maps.Keys(doc.Services))
	var builders []string
	for _, name := range names {
		if err := validate.DNSLabel(name); err != nil {
			return nil, composeRefusef("service name: %s", q(err.Error()))
		}
		if doc.Services[name].Build.Kind != 0 {
			builders = append(builders, name)
		}
	}
	if len(builders) != 1 {
		return nil, composeRefusef("exactly one service must build (the application previewd builds from the root Dockerfile), found %d", len(builders))
	}

	spec := &ComposeSpec{}
	used := map[string]bool{}
	for _, name := range names {
		raw := doc.Services[name]
		svc, err := parseService(name, raw, name == builders[0], declared, allowedImages)
		if err != nil {
			return nil, err
		}
		if err := checkDependsOn(name, raw.DependsOn, doc.Services); err != nil {
			return nil, err
		}
		for _, m := range svc.Mounts {
			used[m.Volume] = true
		}
		if name == builders[0] {
			spec.Primary = svc
		} else {
			spec.Sidecars = append(spec.Sidecars, svc)
		}
	}
	spec.Volumes = slices.Sorted(maps.Keys(used))
	return spec, nil
}

// declaredVolumes returns the names of the top-level volumes. A declaration
// must be empty: a driver, a driver option or an external flag could make
// the named volume a bind mount of a host path.
func declaredVolumes(volumes map[string]yaml.Node) (map[string]bool, error) {
	out := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(volumes)) {
		if err := validate.DNSLabel(name); err != nil {
			return nil, composeRefusef("volumes: volume name: %s", q(err.Error()))
		}
		n := volumes[name]
		empty := (n.Kind == yaml.ScalarNode && n.Tag == "!!null") || (n.Kind == yaml.MappingNode && len(n.Content) == 0)
		if !empty {
			return nil, composeRefusef("volumes: %s takes no option (a driver, option or external flag is refused)", q(name))
		}
		out[name] = true
	}
	return out, nil
}

func parseService(name string, raw rawSvc, primary bool, declared map[string]bool, allowedImages map[string]bool) (ComposeService, error) {
	svc := ComposeService{Name: name}
	for _, key := range slices.Sorted(maps.Keys(raw.Rest)) {
		return svc, composeRefusef("service %s: key %s is not supported", q(name), q(key))
	}
	var err error
	if primary {
		// The primary runs the build; an image it names is never used.
		if err := checkBuild(name, raw.Build); err != nil {
			return svc, err
		}
	} else {
		if raw.Build.Kind != 0 {
			return svc, composeRefusef("service %s: only the application builds (a second build is refused)", q(name))
		}
		if svc.Image, err = sidecarImage(name, raw.Image, allowedImages); err != nil {
			return svc, err
		}
	}
	if svc.Env, err = parseEnv(name, raw.Environment); err != nil {
		return svc, err
	}
	if svc.Command, err = parseCommand(name, raw.Command); err != nil {
		return svc, err
	}
	if svc.Mounts, err = parseMounts(name, raw.Volumes, declared); err != nil {
		return svc, err
	}
	svc.IgnoredPorts = countEntries(raw.Ports) + countEntries(raw.Expose)
	return svc, nil
}

// checkBuild accepts the build of the root context only: previewd builds its
// root Dockerfile with a locked request, so another context, Dockerfile,
// target or argument would not be honored.
func checkBuild(svc string, n yaml.Node) error {
	rootContext := func(v *yaml.Node) bool {
		return v.Kind == yaml.ScalarNode && (v.Value == "." || v.Value == "./")
	}
	switch {
	case rootContext(&n):
		return nil
	case n.Kind == yaml.MappingNode && len(n.Content) == 2 && n.Content[0].Value == "context" && rootContext(n.Content[1]):
		return nil
	}
	return composeRefusef("service %s: build must be the root context (\".\"): previewd builds the root Dockerfile only", q(svc))
}

func sidecarImage(svc, ref string, allowed map[string]bool) (string, error) {
	if ref == "" {
		return "", composeRefusef("service %s: a sidecar needs an image", q(svc))
	}
	canonical, err := validate.BaseImage(ref)
	if err != nil {
		return "", composeRefusef("service %s: image: %s", q(svc), q(err.Error()))
	}
	if !allowed[canonical] {
		return "", composeRefusef("service %s: image %s is not allowed: list it in PREVIEWD_ALLOWED_BASE_IMAGES (previewd never pulls)", q(svc), q(canonical))
	}
	return canonical, nil
}

// parseEnv reads environment as a map or as KEY=value items. A variable
// without a value would inherit it from previewd's own environment: refused.
// Values are passed literally; no interpolation is performed, so a reference
// to one is refused instead of being passed as text.
func parseEnv(svc string, n yaml.Node) ([]string, error) {
	vars := map[string]string{}
	add := func(key, value string) error {
		if err := validate.EnvName(key); err != nil {
			return composeRefusef("service %s: environment: %s", q(svc), q(err.Error()))
		}
		if _, dup := vars[key]; dup {
			return composeRefusef("service %s: environment sets %s twice", q(svc), q(key))
		}
		switch {
		case len(value) > maxComposeEnvBytes || strings.ContainsRune(value, 0):
			return composeRefusef("service %s: environment %s must be at most %d bytes without a NUL", q(svc), q(key), maxComposeEnvBytes)
		case strings.Contains(value, "${"):
			return composeRefusef("service %s: environment %s uses variable interpolation, which previewd does not perform", q(svc), q(key))
		}
		vars[key] = value
		return nil
	}
	switch n.Kind {
	case 0:
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode || v.Tag == "!!null" {
				return nil, composeRefusef("service %s: environment %s needs a literal value (inheriting the host's environment is refused)", q(svc), q(k.Value))
			}
			if err := add(k.Value, v.Value); err != nil {
				return nil, err
			}
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			key, value, ok := strings.Cut(item.Value, "=")
			if item.Kind != yaml.ScalarNode || !ok {
				return nil, composeRefusef("service %s: environment items must be KEY=value (inheriting the host's environment is refused)", q(svc))
			}
			if err := add(key, value); err != nil {
				return nil, err
			}
		}
	default:
		return nil, composeRefusef("service %s: environment must be a map or a list", q(svc))
	}
	if len(vars) > maxComposeEnv {
		return nil, composeRefusef("service %s: %d environment variables, above %d", q(svc), len(vars), maxComposeEnv)
	}
	out := make([]string, 0, len(vars))
	for _, k := range slices.Sorted(maps.Keys(vars)) {
		out = append(out, k+"="+vars[k])
	}
	return out, nil
}

// parseCommand accepts the list form only: previewd does not split a shell
// string.
func parseCommand(svc string, n yaml.Node) ([]string, error) {
	switch n.Kind {
	case 0:
		return nil, nil
	case yaml.SequenceNode:
	default:
		return nil, composeRefusef("service %s: command must be a list of arguments", q(svc))
	}
	if len(n.Content) > maxComposeCommand {
		return nil, composeRefusef("service %s: command has %d arguments, above %d", q(svc), len(n.Content), maxComposeCommand)
	}
	out := make([]string, 0, len(n.Content))
	for _, a := range n.Content {
		if a.Kind != yaml.ScalarNode || len(a.Value) > maxComposeEnvBytes || strings.ContainsRune(a.Value, 0) {
			return nil, composeRefusef("service %s: command arguments must be scalars of at most %d bytes", q(svc), maxComposeEnvBytes)
		}
		out = append(out, a.Value)
	}
	return out, nil
}

// parseMounts reads volumes in the short (name:/target[:ro]) or the long
// ({type: volume, source, target, read_only}) syntax. Only a declared named
// volume is accepted.
func parseMounts(svc string, n yaml.Node, declared map[string]bool) ([]ComposeMount, error) {
	switch n.Kind {
	case 0:
		return nil, nil
	case yaml.SequenceNode:
	default:
		return nil, composeRefusef("service %s: volumes must be a list", q(svc))
	}
	if len(n.Content) > maxComposeMounts {
		return nil, composeRefusef("service %s: %d volumes, above %d", q(svc), len(n.Content), maxComposeMounts)
	}
	var out []ComposeMount
	targets := map[string]bool{}
	for _, item := range n.Content {
		var (
			m   ComposeMount
			err error
		)
		switch item.Kind {
		case yaml.ScalarNode:
			m, err = shortMount(svc, item.Value)
		case yaml.MappingNode:
			m, err = longMount(svc, item)
		default:
			err = composeRefusef("service %s: a volume must be a string or a map", q(svc))
		}
		if err != nil {
			return nil, err
		}
		if !declared[m.Volume] {
			return nil, composeRefusef("service %s: volume %s is not declared in the top-level volumes", q(svc), q(m.Volume))
		}
		if err := checkMountTarget(svc, m.Target); err != nil {
			return nil, err
		}
		if targets[m.Target] {
			return nil, composeRefusef("service %s: two volumes mount at target %s", q(svc), q(m.Target))
		}
		targets[m.Target] = true
		out = append(out, m)
	}
	return out, nil
}

func hostPathLike(source string) bool {
	return strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") || strings.HasPrefix(source, "~") ||
		strings.ContainsAny(source, `/\`)
}

func shortMount(svc, s string) (ComposeMount, error) {
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		return ComposeMount{}, composeRefusef("service %s: volume %s is an anonymous volume: name it and declare it in the top-level volumes", q(svc), q(s))
	}
	source := parts[0]
	if hostPathLike(source) {
		return ComposeMount{}, composeRefusef("service %s: host bind mount %s is forbidden: only named volumes", q(svc), q(source))
	}
	if err := validate.DNSLabel(source); err != nil {
		return ComposeMount{}, composeRefusef("service %s: volume name: %s", q(svc), q(err.Error()))
	}
	m := ComposeMount{Volume: source, Target: parts[1]}
	switch {
	case len(parts) == 2:
	case len(parts) == 3 && parts[2] == "rw":
	case len(parts) == 3 && parts[2] == "ro":
		m.ReadOnly = true
	default:
		return ComposeMount{}, composeRefusef("service %s: volume %s has a mode other than ro or rw", q(svc), q(s))
	}
	return m, nil
}

func longMount(svc string, n *yaml.Node) (ComposeMount, error) {
	var typ, source string
	m := ComposeMount{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return m, composeRefusef("service %s: volume key %s must be a scalar", q(svc), q(k))
		}
		switch k {
		case "type":
			typ = v.Value
		case "source":
			source = v.Value
		case "target":
			m.Target = v.Value
		case "read_only":
			m.ReadOnly = v.Value == "true"
			if v.Value != "true" && v.Value != "false" {
				return m, composeRefusef("service %s: volume read_only must be true or false", q(svc))
			}
		default:
			return m, composeRefusef("service %s: volume key %s is not supported", q(svc), q(k))
		}
	}
	switch typ {
	case "volume":
	case "bind":
		return m, composeRefusef("service %s: host bind mount is forbidden: only named volumes", q(svc))
	default:
		return m, composeRefusef("service %s: volume type %s is not supported: only named volumes", q(svc), q(typ))
	}
	if hostPathLike(source) {
		return m, composeRefusef("service %s: host bind mount %s is forbidden: only named volumes", q(svc), q(source))
	}
	if source == "" {
		return m, composeRefusef("service %s: volume without a source is an anonymous volume", q(svc))
	}
	if err := validate.DNSLabel(source); err != nil {
		return m, composeRefusef("service %s: volume name: %s", q(svc), q(err.Error()))
	}
	m.Volume = source
	return m, nil
}

// checkMountTarget refuses a relative or unclean target, and the paths the
// daemon owns or previewd mounts itself.
func checkMountTarget(svc, target string) error {
	if !path.IsAbs(target) || path.Clean(target) != target || target == "/" {
		return composeRefusef("service %s: volume target %s must be a clean absolute path", q(svc), q(target))
	}
	for _, reserved := range []string{SecretsMountTarget, "/proc", "/sys", "/dev"} {
		if target == reserved || strings.HasPrefix(target, reserved+"/") {
			return composeRefusef("service %s: volume target %s is under %s", q(svc), q(target), reserved)
		}
	}
	return nil
}

// countEntries is the number of entries of a ports or expose list: dropped,
// never published.
func countEntries(n yaml.Node) int {
	switch n.Kind {
	case 0:
		return 0
	case yaml.SequenceNode:
		return len(n.Content)
	default:
		return 1
	}
}

// checkDependsOn verifies that every service a service depends on exists.
// Start order is previewd's own (sidecars first), so the conditions are not
// read.
func checkDependsOn(svc string, n yaml.Node, services map[string]rawSvc) error {
	var deps []string
	switch n.Kind {
	case 0:
	case yaml.SequenceNode:
		for _, d := range n.Content {
			deps = append(deps, d.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			deps = append(deps, n.Content[i].Value)
		}
	default:
		return composeRefusef("service %s: depends_on must be a list or a map", q(svc))
	}
	for _, d := range deps {
		if _, ok := services[d]; !ok {
			return composeRefusef("service %s: depends_on names an unknown service %s", q(svc), q(d))
		}
	}
	return nil
}

// LoadCompose reads the compose file of an extracted checkout: previewd.compose.yml,
// else docker-compose.yml. It returns nil, "" when neither exists. The file
// must be a regular file at the root (never a link or a directory, which
// could point out of the checkout) of at most maxComposeBytes; a larger one
// is refused, never truncated. A previewd.compose.yml that is invalid does
// not fall back to the other file.
func LoadCompose(srcDir string) ([]byte, string, error) {
	root, err := os.OpenRoot(srcDir)
	if err != nil {
		return nil, "", fmt.Errorf("open checkout: %w", err)
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{composeFileName, composeFallbackName} {
		fi, err := root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("stat %s: %w", name, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, "", composeRefusef("%s is a %s: only a regular file is read", name, fi.Mode().Type())
		}
		if fi.Size() > maxComposeBytes {
			return nil, "", composeRefusef("%s is %d bytes, above the %d-byte cap", name, fi.Size(), maxComposeBytes)
		}
		f, err := root.Open(name)
		if err != nil {
			return nil, "", fmt.Errorf("open %s: %w", name, err)
		}
		data, err := io.ReadAll(io.LimitReader(f, maxComposeBytes+1))
		closeErr := f.Close()
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", name, err)
		}
		if closeErr != nil {
			return nil, "", fmt.Errorf("close %s: %w", name, closeErr)
		}
		if len(data) > maxComposeBytes {
			return nil, "", composeRefusef("%s grew past the %d-byte cap while read", name, maxComposeBytes)
		}
		return data, name, nil
	}
	return nil, "", nil
}
