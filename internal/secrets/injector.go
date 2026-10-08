package secrets

// The secrets file (V1 spec D5, D-V1-1, V1-I2) is split per repository and
// per trust level:
//
//	# comments and blank lines are ignored
//	[acme/app]
//	DB_PASSWORD=...           the trusted set: same-repository PRs by a writer
//	[acme/app:untrusted]
//	DB_PASSWORD=...           what an approved fork or external PR receives
//
// Every key belongs to exactly one section: there is no global set, so no
// key reaches another repository, and an untrusted deploy reads only its
// ":untrusted" section. A missing section is an empty set, never another
// section. Any malformed line refuses the whole file; errors name the line
// number, never its content.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// untrustedSuffix marks a repository's untrusted section.
	untrustedSuffix = ":untrusted"
	// maxSecretsFileBytes bounds the secrets file.
	maxSecretsFileBytes = 1 << 20
)

// Injector holds the parsed secrets file in memory. It is immutable once
// loaded.
type Injector struct {
	sections map[string]map[string]string // "owner/repo" or "owner/repo:untrusted" -> key -> value
}

// NewInjector parses the secrets file at filePath into memory. A missing
// file is an empty set: every section is empty. A file that does not
// parse refuses to start.
func NewInjector(filePath string) (*Injector, error) {
	inj := &Injector{sections: map[string]map[string]string{}}
	root, err := os.OpenRoot(filepath.Dir(filePath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inj, nil
		}
		return nil, fmt.Errorf("open the secrets directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(filepath.Base(filePath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inj, nil
		}
		return nil, fmt.Errorf("open the secrets file: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxSecretsFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the secrets file: %w", err)
	}
	defer clear(data)
	if len(data) > maxSecretsFileBytes {
		return nil, fmt.Errorf("the secrets file exceeds %d bytes", maxSecretsFileBytes)
	}
	if inj.sections, err = parseSections(data); err != nil {
		return nil, fmt.Errorf("secrets file: %w", err)
	}
	return inj, nil
}

// parseSections parses the sectioned format. Errors carry line numbers and
// section names only, never a value.
func parseSections(data []byte) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	folded := map[string]int{} // case-folded section name -> line declared
	var current map[string]string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxSecretsFileBytes)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "["):
			name, err := sectionName(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			if first, dup := folded[strings.ToLower(name)]; dup {
				return nil, fmt.Errorf("line %d: section [%s] already declared on line %d", n, name, first)
			}
			folded[strings.ToLower(name)] = n
			current = map[string]string{}
			sections[name] = current
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		switch {
		case current == nil:
			return nil, fmt.Errorf("line %d: a key outside any [owner/repo] section: every secret belongs to one repository", n)
		case !ok:
			return nil, fmt.Errorf("line %d: want KEY=value", n)
		case !secretKeyPattern.MatchString(key):
			return nil, fmt.Errorf("line %d: invalid key: want [A-Za-z_][A-Za-z0-9_]*, at most 128 bytes", n)
		}
		if _, dup := current[key]; dup {
			return nil, fmt.Errorf("line %d: key %s set twice in its section", n, key)
		}
		current[key] = strings.TrimSpace(value)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return sections, nil
}

// sectionName parses "[owner/repo]" or "[owner/repo:untrusted]".
func sectionName(line string) (string, error) {
	inner, ok := strings.CutSuffix(strings.TrimPrefix(line, "["), "]")
	if !ok {
		return "", errors.New("a section header must end with ]")
	}
	repo, suffix, hasSuffix := strings.Cut(inner, ":")
	if hasSuffix && ":"+suffix != untrustedSuffix {
		return "", errors.New("a section is [owner/repo] or [owner/repo:untrusted]")
	}
	if validate.RepoFullName(repo) != nil {
		// The validator quotes its input: a header line could be a value
		// pasted out of place, so it is never repeated.
		return "", errors.New("a section header names an owner/repo repository")
	}
	return inner, nil
}

// Section returns a copy of the secrets a deploy of repo receives:
//   - trusted (untrusted false): the [repo] section;
//   - untrusted: the [repo:untrusted] section, never [repo]; a missing
//     untrusted section is an empty map;
//   - untrusted with fullOptIn (D-V1-1, PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS):
//     the [repo] section.
//
// fullOptIn without untrusted is a caller error. A repository without a
// section gets an empty map.
func (i *Injector) Section(repo string, untrusted, fullOptIn bool) (map[string]string, error) {
	if err := validate.RepoFullName(repo); err != nil {
		return nil, fmt.Errorf("secrets section: %w", err)
	}
	if fullOptIn && !untrusted {
		return nil, errors.New("secrets section: the full-secrets opt-in applies to an untrusted deploy only")
	}
	name := repo
	if untrusted && !fullOptIn {
		name = repo + untrustedSuffix
	}
	out := make(map[string]string, len(i.sections[name]))
	maps.Copy(out, i.sections[name])
	return out, nil
}
