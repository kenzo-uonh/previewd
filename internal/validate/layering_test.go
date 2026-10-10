package validate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const internalPrefix = "github.com/kenzo-uonh/previewd/internal/"

// allowedImports is the package layering of internal/. A new import edge is
// an architecture change: add it here and justify it in the commit. A new
// package needs its own entry.
var allowedImports = map[string][]string{
	// Leaves: no internal import.
	"envid":     {},
	"hardening": {},
	"textutil":  {},
	"validate":  {},

	// config parses the approver list and the approval label with the
	// validators the webhook path uses (V1 F1): one definition of a valid
	// login, repository and label, refused at start.
	"config": {"validate"},
	// The credential reader shares the credential-name rule with config.
	"secrets": {"validate"},
	"store":   {},
	// The GHES client (C3) validates every reply with the webhook path's
	// validators and quotes replies in errors only through textutil.
	"vcs":   {"textutil", "validate"},
	"proxy": {"envid", "validate"},
	// The reconciler consumes the queue (store) and publishes routes (proxy);
	// envid validates ownership labels at startup. Fetching and secrets come
	// in through injected functions and interfaces.
	// textutil bounds untrusted daemon output (build errors quote the PR's
	// Dockerfile) before it reaches an error or a log line.
	// The authorizer (D4) judges GHES truth with the vcs types and trust
	// rule (vcs.PRState, vcs.Trusted, vcs.WriteAccess: one definition, shared
	// with the webhook handler) and matches approvers on the
	// validate.Approver list config parses.
	"orchestrator": {"envid", "proxy", "store", "textutil", "validate", "vcs"},
	// The handler writes to the queue and wakes the reconciler through
	// consumer interfaces: no orchestrator import.
	"api": {"config", "envid", "store", "validate", "vcs"},
}

var leaves = []string{"envid", "hardening", "textutil", "validate"}

func TestPackageLayering(t *testing.T) {
	root := filepath.Join("..")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg := e.Name()
		imports, err := internalImports(filepath.Join(root, pkg))
		if err != nil {
			t.Fatal(err)
		}
		if len(imports) == 0 && !hasGoFiles(t, filepath.Join(root, pkg)) {
			continue
		}
		allowed, ok := allowedImports[pkg]
		if !ok {
			t.Errorf("internal/%s has no layering entry: add it to allowedImports", pkg)
			continue
		}
		for _, imp := range imports {
			if !contains(allowed, imp) {
				t.Errorf("internal/%s imports internal/%s: edge not in allowedImports", pkg, imp)
			}
		}
	}

	for _, leaf := range leaves {
		if len(allowedImports[leaf]) != 0 {
			t.Errorf("leaf %s must not be allowed any internal import", leaf)
		}
	}
}

// internalImports lists the internal packages imported by non-test files.
func internalImports(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, err
			}
			if rest, ok := strings.CutPrefix(path, internalPrefix); ok {
				seen[strings.SplitN(rest, "/", 2)[0]] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func hasGoFiles(t *testing.T, dir string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	return len(files) > 0
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
