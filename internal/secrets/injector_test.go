package secrets

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sectionedFile = `# previewd secrets
[acme/app]
DB_PASSWORD = trusted-db-password
API_TOKEN=trusted=token=with=equals

[acme/app:untrusted]
DB_PASSWORD=sandbox-db-password

[acme/other]
OTHER_KEY=other-repo-only

[acme/bare:untrusted]
`

// trustedValues are the values no untrusted deploy may ever receive.
var trustedValues = []string{"trusted-db-password", "trusted=token=with=equals", "other-repo-only"}

func loadInjector(t *testing.T, content string) *Injector {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	inj, err := NewInjector(path)
	if err != nil {
		t.Fatal(err)
	}
	return inj
}

func section(t *testing.T, inj *Injector, repo string, untrusted, full bool) map[string]string {
	t.Helper()
	got, err := inj.Section(repo, untrusted, full)
	if err != nil {
		t.Fatalf("Section(%s, untrusted=%v, full=%v): %v", repo, untrusted, full, err)
	}
	return got
}

func TestSectionByTrust(t *testing.T) {
	inj := loadInjector(t, sectionedFile)
	for name, tc := range map[string]struct {
		repo            string
		untrusted, full bool
		want            map[string]string
	}{
		"trusted":                      {"acme/app", false, false, map[string]string{"DB_PASSWORD": "trusted-db-password", "API_TOKEN": "trusted=token=with=equals"}},
		"untrusted":                    {"acme/app", true, false, map[string]string{"DB_PASSWORD": "sandbox-db-password"}},
		"untrusted, D-V1-1 opt-in":     {"acme/app", true, true, map[string]string{"DB_PASSWORD": "trusted-db-password", "API_TOKEN": "trusted=token=with=equals"}},
		"untrusted, no section":        {"acme/other", true, false, map[string]string{}},
		"untrusted, empty section":     {"acme/bare", true, false, map[string]string{}},
		"trusted, only untrusted":      {"acme/bare", false, false, map[string]string{}},
		"repository without a section": {"acme/none", false, false, map[string]string{}},
		"case differs":                 {"Acme/App", false, false, map[string]string{}},
	} {
		if got := section(t, inj, tc.repo, tc.untrusted, tc.full); !maps.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// V1-I2, fail closed: an untrusted deploy (without the opt-in) never
// receives a trusted key, whatever the file holds: no section, an empty
// section, or another repository's sections. A returned map is a copy.
func TestUntrustedNeverReceivesATrustedKey(t *testing.T) {
	inj := loadInjector(t, sectionedFile)
	for _, repo := range []string{"acme/app", "acme/other", "acme/bare", "acme/none"} {
		got := section(t, inj, repo, true, false)
		for k, v := range got {
			for _, trusted := range trustedValues {
				if v == trusted {
					t.Errorf("untrusted deploy of %s received trusted %s", repo, k)
				}
			}
		}
	}
	got := section(t, inj, "acme/app", true, false)
	got["DB_PASSWORD"] = "tampered"
	if again := section(t, inj, "acme/app", true, false); again["DB_PASSWORD"] != "sandbox-db-password" {
		t.Fatal("Section returned the injector's own map")
	}
}

// Fail closed: a malformed file refuses to load, and the error names the
// line, never a value.
func TestSecretsFileRefusesMalformedInput(t *testing.T) {
	const secret = "s3cr3t-never-in-errors"
	for name, content := range map[string]string{
		"key outside any section":   "TOKEN=" + secret + "\n[acme/app]\n",
		"no equals sign":            "[acme/app]\n" + secret + "\n",
		"invalid key":               "[acme/app]\n9KEY=" + secret + "\n",
		"key with a dash":           "[acme/app]\nMY-KEY=" + secret + "\n",
		"duplicate key":             "[acme/app]\nK=" + secret + "\nK=other\n",
		"duplicate section":         "[acme/app]\nK=1\n[acme/app]\nK=" + secret + "\n",
		"section differing by case": "[acme/app]\nK=1\n[Acme/App]\nK=" + secret + "\n",
		"unknown suffix":            "[acme/app:sandbox]\nK=" + secret + "\n",
		"unclosed header":           "[acme/app\nK=" + secret + "\n",
		"not a repository":          "[" + secret + "]\nK=1\n",
		"path in header":            "[../etc/passwd]\nK=" + secret + "\n",
		"empty header":              "[]\nK=" + secret + "\n",
		"too large":                 "[acme/app]\nK=" + strings.Repeat("x", maxSecretsFileBytes) + "\n",
	} {
		path := filepath.Join(t.TempDir(), "secrets.env")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		inj, err := NewInjector(path)
		if err == nil {
			t.Errorf("%s: loaded %v", name, inj)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error quotes a secret: %v", name, err)
		}
	}
}

func TestSectionRefusesInvalidRequests(t *testing.T) {
	inj := loadInjector(t, sectionedFile)
	for _, repo := range []string{"", "acme", "acme/app:untrusted", "../acme/app", "acme/app/extra"} {
		if got, err := inj.Section(repo, true, false); err == nil {
			t.Errorf("Section(%q) = %v", repo, got)
		}
	}
	if got, err := inj.Section("acme/app", false, true); err == nil {
		t.Errorf("the opt-in on a trusted request: %v", got)
	}
}

// A missing file is an empty set: every section is empty.
func TestMissingSecretsFileIsEmpty(t *testing.T) {
	inj, err := NewInjector(filepath.Join(t.TempDir(), "absent", "secrets.env"))
	if err != nil {
		t.Fatal(err)
	}
	if got := section(t, inj, "acme/app", false, false); len(got) != 0 {
		t.Fatalf("missing file: %v", got)
	}
}
