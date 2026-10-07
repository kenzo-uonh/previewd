package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/envid"
	"gopkg.in/yaml.v3"
	"pgregory.net/rapid"
)

func domainGen() *rapid.Generator[string] {
	label := rapid.StringMatching(`[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?`)
	return rapid.Map(rapid.SliceOfN(label, 1, 4), func(ls []string) string { return strings.Join(ls, ".") })
}

func backendGen() *rapid.Generator[netip.AddrPort] {
	return rapid.Custom(func(t *rapid.T) netip.AddrPort {
		var addr netip.Addr
		if rapid.Bool().Draw(t, "v6") {
			addr = netip.AddrFrom16([16]byte(rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "ip6")))
		} else {
			addr = netip.AddrFrom4([4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "ip4")))
		}
		if addr.IsUnspecified() || addr.IsMulticast() {
			t.Skip("not a unicast backend")
		}
		return netip.AddrPortFrom(addr, rapid.Uint16Range(1, 65535).Draw(t, "port"))
	})
}

func routeGen() *rapid.Generator[Route] {
	return rapid.Custom(func(t *rapid.T) Route {
		return Route{
			EnvID:   envid.Generate(rapid.String().Draw(t, "repo"), rapid.String().Draw(t, "branch"), rapid.Uint64().Draw(t, "pr")),
			Domain:  domainGen().Draw(t, "domain"),
			Backend: backendGen().Draw(t, "backend"),
		}
	})
}

// strictJSON decodes like a schema check: no unknown field, no trailing data.
func strictJSON(b []byte) (Document, error) {
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Document{}, err
	}
	if dec.More() {
		return Document{}, fmt.Errorf("trailing data")
	}
	return doc, nil
}

// Invariant 1: syntactic validity. Every rendered document decodes with
// gopkg.in/yaml.v3 (the parser Traefik's file provider uses, via
// traefik/paerser) and as strict JSON, and rendering is deterministic.
func TestRenderIsValidYAMLAndJSON(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		r := routeGen().Draw(t, "route")
		out, err := Render(r)
		if err != nil {
			if r.Validate() == nil {
				t.Fatalf("Render(%+v) failed on a valid route: %v", r, err)
			}
			return
		}

		var viaYAML Document
		if err := yaml.Unmarshal(out, &viaYAML); err != nil {
			t.Fatalf("YAML decode of %s: %v", out, err)
		}
		viaJSON, err := strictJSON(out)
		if err != nil {
			t.Fatalf("strict JSON decode of %s: %v", out, err)
		}
		want, err := r.Document()
		if err != nil {
			t.Fatal(err)
		}
		for name, got := range map[string]Document{"yaml": viaYAML, "json": viaJSON} {
			if !equalDocuments(got, want) {
				t.Fatalf("%s decode = %+v, want %+v", name, got, want)
			}
		}
		if again, _ := Render(r); !bytes.Equal(again, out) {
			t.Fatal("Render is not deterministic")
		}
	})
}

// Invariant 2: routing integrity. Traefik merges every file in the routes
// directory; after merging, each environment's host reaches exactly its own
// backend and no name is shared between environments.
func TestMergedRoutesHaveNoCrossTalk(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 8).Draw(t, "n")
		domain := domainGen().Draw(t, "domain")
		routes := make([]Route, 0, n)
		seen := map[string]bool{}
		for i := range n {
			r := Route{
				EnvID:   envid.Generate(rapid.String().Draw(t, "repo"), rapid.String().Draw(t, "branch"), uint64(i)+1),
				Domain:  domain,
				Backend: backendGen().Draw(t, "backend"),
			}
			if seen[r.EnvID] {
				t.Skip("duplicate environment")
			}
			seen[r.EnvID] = true
			routes = append(routes, r)
		}

		merged := HTTPConfig{Routers: map[string]Router{}, Services: map[string]Service{}}
		for _, r := range routes {
			out, err := Render(r)
			if err != nil {
				t.Fatalf("Render(%+v): %v", r, err)
			}
			var doc Document
			if err := yaml.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.HTTP.Routers) != 1 || len(doc.HTTP.Services) != 1 {
				t.Fatalf("document of %s holds %d routers, %d services", r.EnvID, len(doc.HTTP.Routers), len(doc.HTTP.Services))
			}
			for name, rt := range doc.HTTP.Routers {
				if _, dup := merged.Routers[name]; dup {
					t.Fatalf("router %q defined by two environments", name)
				}
				merged.Routers[name] = rt
			}
			for name, svc := range doc.HTTP.Services {
				if _, dup := merged.Services[name]; dup {
					t.Fatalf("service %q defined by two environments", name)
				}
				merged.Services[name] = svc
			}
		}

		for _, r := range routes {
			rt, ok := merged.Routers[r.EnvID]
			if !ok {
				t.Fatalf("no router for %s", r.EnvID)
			}
			if want := "Host(`" + r.EnvID + "." + domain + "`)"; rt.Rule != want {
				t.Fatalf("router %s rule = %q, want %q", r.EnvID, rt.Rule, want)
			}
			if rt.Service != r.EnvID || len(rt.EntryPoints) != 1 || rt.EntryPoints[0] != EntryPoint {
				t.Fatalf("router %s = %+v", r.EnvID, rt)
			}
			servers := merged.Services[rt.Service].LoadBalancer.Servers
			if len(servers) != 1 || servers[0].URL != "http://"+r.Backend.String() {
				t.Fatalf("host of %s reaches %+v, want only %s", r.EnvID, servers, r.Backend)
			}
		}
	})
}

// No input reaches the document unless it passed its validator: a hostile
// environment ID or domain cannot inject into the rule or the URL.
func TestRenderRejectsUntrustedInput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		r := Route{
			EnvID:   rapid.OneOf(rapid.String(), rapid.StringMatching(`pr-[0-9]{1,3}-[0-9a-f]{10}`)).Draw(t, "env"),
			Domain:  rapid.OneOf(rapid.String(), domainGen(), rapid.SampledFrom([]string{"a`) || Host(`b", "x.y\nz", "x..y", "X.Y"})).Draw(t, "domain"),
			Backend: backendGen().Draw(t, "backend"),
		}
		out, err := Render(r)
		if err != nil {
			return
		}
		if !envid.Valid(r.EnvID) || strings.ContainsAny(r.Domain, "`()| \n\"\\") {
			t.Fatalf("Render accepted env=%q domain=%q:\n%s", r.EnvID, r.Domain, out)
		}
	})
}

func TestRouteValidateRejectsBadBackends(t *testing.T) {
	base := Route{EnvID: envid.Generate("acme/shop", "main", 7), Domain: "preview.example"}
	for _, b := range []netip.AddrPort{
		{},
		netip.MustParseAddrPort("10.0.0.2:0"),
		netip.MustParseAddrPort("0.0.0.0:80"),
		netip.MustParseAddrPort("[::]:80"),
		netip.MustParseAddrPort("224.0.0.1:80"),
		netip.AddrPortFrom(netip.MustParseAddr("fe80::1%eth0"), 80),
	} {
		r := base
		r.Backend = b
		if err := r.Validate(); err == nil {
			t.Errorf("Validate accepted backend %v", b)
		}
	}
}

func equalDocuments(a, b Document) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}
