package proxy

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"github.com/kenzo-uonh/previewd/internal/validate"
)

// EntryPoint is the Traefik entry point every preview route binds to.
const EntryPoint = "web"

const maxHostLen = 253

// Route is the Traefik file-provider route of one environment: requests for
// Host(<EnvID>.<Domain>) go to Backend, and nowhere else.
type Route struct {
	EnvID   string
	Domain  string
	Backend netip.AddrPort
}

// Document is the Traefik dynamic configuration written for one environment.
// It is encoded as JSON, which is also valid YAML: Traefik's file provider
// reads it from a .yml file, and the encoder escapes every value.
type Document struct {
	HTTP HTTPConfig `json:"http" yaml:"http"`
}

// HTTPConfig holds exactly one router and one service, both named after the
// environment.
type HTTPConfig struct {
	Routers  map[string]Router  `json:"routers" yaml:"routers"`
	Services map[string]Service `json:"services" yaml:"services"`
}

// Router matches the environment's host name.
type Router struct {
	Rule        string   `json:"rule" yaml:"rule"`
	Service     string   `json:"service" yaml:"service"`
	EntryPoints []string `json:"entryPoints" yaml:"entryPoints"`
}

// Service forwards to the environment's container.
type Service struct {
	LoadBalancer LoadBalancer `json:"loadBalancer" yaml:"loadBalancer"`
}

// LoadBalancer lists the backend servers.
type LoadBalancer struct {
	Servers []Server `json:"servers" yaml:"servers"`
}

// Server is one backend URL.
type Server struct {
	URL string `json:"url" yaml:"url"`
}

// Host returns the host name the route answers for.
func (r Route) Host() string {
	return r.EnvID + "." + r.Domain
}

// Validate refuses any route whose values could break out of the rule or
// the URL, or that points to no reachable backend.
func (r Route) Validate() error {
	if !envid.Valid(r.EnvID) {
		return fmt.Errorf("route: invalid environment id %q", r.EnvID)
	}
	if err := validate.DNSName(r.Domain); err != nil {
		return fmt.Errorf("route %s: %w", r.EnvID, err)
	}
	if len(r.Host()) > maxHostLen {
		return fmt.Errorf("route %s: host name exceeds %d bytes", r.EnvID, maxHostLen)
	}
	addr := r.Backend.Addr()
	if !r.Backend.IsValid() || r.Backend.Port() == 0 || addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
		return fmt.Errorf("route %s: invalid backend %s", r.EnvID, r.Backend)
	}
	return nil
}

// Document builds the route's Traefik configuration.
func (r Route) Document() (Document, error) {
	if err := r.Validate(); err != nil {
		return Document{}, err
	}
	return Document{HTTP: HTTPConfig{
		Routers: map[string]Router{r.EnvID: {
			Rule:        "Host(`" + r.Host() + "`)",
			Service:     r.EnvID,
			EntryPoints: []string{EntryPoint},
		}},
		Services: map[string]Service{r.EnvID: {
			LoadBalancer: LoadBalancer{Servers: []Server{{URL: "http://" + r.Backend.String()}}},
		}},
	}}, nil
}

// Render encodes the route document. The output is deterministic.
func Render(r Route) ([]byte, error) {
	doc, err := r.Document()
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode route %s: %w", r.EnvID, err)
	}
	return append(out, '\n'), nil
}
