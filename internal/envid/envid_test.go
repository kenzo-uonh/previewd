package envid

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// RFC 1123 label: lowercase alphanumerics and '-', no leading or trailing '-'.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// anyString draws valid UTF-8 text and arbitrary bytes alike: repository and
// branch names arrive from webhooks.
func anyString() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.String(),
		rapid.Map(rapid.SliceOf(rapid.Byte()), func(b []byte) string { return string(b) }),
	)
}

// Invariant 1: canonical DNS validity.
func TestGenerateIsDNSLabel(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := Generate(anyString().Draw(t, "repo"), anyString().Draw(t, "branch"), rapid.Uint64().Draw(t, "pr"))
		if len(id) > MaxLen {
			t.Fatalf("len(%q) = %d > %d", id, len(id), MaxLen)
		}
		if !dnsLabel.MatchString(id) {
			t.Fatalf("%q is not an RFC 1123 label", id)
		}
	})
}

// Invariant 2: PR ID preservation.
func TestParsePRRecoversGeneratedID(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pr := rapid.Uint64().Draw(t, "pr")
		id := Generate(anyString().Draw(t, "repo"), anyString().Draw(t, "branch"), pr)
		got, err := ParsePR(id)
		if err != nil {
			t.Fatalf("ParsePR(%q): %v", id, err)
		}
		if got != pr {
			t.Fatalf("ParsePR(Generate(_, _, %d)) = %d", pr, got)
		}
	})
}

// Invariant 3: determinism, including GitHub's ASCII case-insensitive
// repository names.
func TestGenerateIsDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		repo := anyString().Draw(t, "repo")
		branch := anyString().Draw(t, "branch")
		pr := rapid.Uint64().Draw(t, "pr")
		if a, b := Generate(repo, branch, pr), Generate(repo, branch, pr); a != b {
			t.Fatalf("Generate not deterministic: %q != %q", a, b)
		}
		if a, b := Generate(repo, branch, pr), Generate(asciiUpper(repo), branch, pr); a != b {
			t.Fatalf("repository case changed the id: %q != %q", a, b)
		}
	})
}

// Isolation between repositories: the same PR number in two repositories
// never shares an environment (40-bit hash; a collision within 10^4 draws
// has probability below 10^-4).
func TestGenerateSeparatesRepositoriesAndBranches(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pr := rapid.Uint64().Draw(t, "pr")
		repoA, repoB := anyString().Draw(t, "repoA"), anyString().Draw(t, "repoB")
		branchA, branchB := anyString().Draw(t, "branchA"), anyString().Draw(t, "branchB")
		if asciiLower(repoA) == asciiLower(repoB) && branchA == branchB {
			t.Skip("same environment")
		}
		if a, b := Generate(repoA, branchA, pr), Generate(repoB, branchB, pr); a == b {
			t.Fatalf("(%q,%q) and (%q,%q) share id %q", repoA, branchA, repoB, branchB, a)
		}
	})
}

// ParsePR is strict: anything it accepts is a canonical, valid label that
// re-renders to itself.
func TestParsePRAcceptsOnlyCanonicalIDs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.OneOf(
			anyString(),
			rapid.StringMatching(`pr-[0-9+-]{0,22}-[0-9a-fA-F]{8,12}`),
		).Draw(t, "s")
		pr, err := ParsePR(s)
		if err != nil {
			return
		}
		if !dnsLabel.MatchString(s) || len(s) > MaxLen {
			t.Fatalf("ParsePR accepted non-label %q", s)
		}
		if want := prefix + strconv.FormatUint(pr, 10) + "-"; !strings.HasPrefix(s, want) {
			t.Fatalf("ParsePR(%q) = %d, not canonical", s, pr)
		}
	})
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

func TestParsePRRejects(t *testing.T) {
	for _, s := range []string{
		"", "pr-", "pr-1", "pr-1-", "pr--0123456789", "pr-01-0123456789", "pr-+1-0123456789",
		"pr-1-012345678", "pr-1-01234567890", "pr-1-ABCDEF0123", "PR-1-0123456789",
		"pr-18446744073709551616-0123456789", "pr-1-0123456789\n", "xpr-1-0123456789",
	} {
		if _, err := ParsePR(s); err == nil {
			t.Errorf("ParsePR(%q) accepted", s)
		}
	}
}
