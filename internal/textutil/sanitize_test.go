package textutil

import (
	"regexp"
	"testing"

	"pgregory.net/rapid"
)

var allowlist = regexp.MustCompile(`^[a-zA-Z0-9-]*$`)

func anyString() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.String(),
		rapid.Map(rapid.SliceOf(rapid.Byte()), func(b []byte) string { return string(b) }),
		rapid.SampledFrom([]string{"../../etc/passwd", "a/b", "$(id)", "`id`", "; rm -rf /", "x\x00y", "é", "\xff\xfe"}),
	)
}

// Invariant 1: idempotency.
func TestSanitizeIsIdempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		once := Sanitize(anyString().Draw(t, "s"))
		if twice := Sanitize(once); twice != once {
			t.Fatalf("Sanitize(Sanitize(x)) = %q, Sanitize(x) = %q", twice, once)
		}
	})
}

// Invariant 2: strict allowlist.
func TestSanitizeOutputIsAllowlisted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if out := Sanitize(anyString().Draw(t, "s")); !allowlist.MatchString(out) {
			t.Fatalf("Sanitize output %q leaves the allowlist", out)
		}
	})
}

// Allowlisted text passes through unchanged, and every rune (or invalid
// byte) of the input maps to exactly one output byte.
func TestSanitizePreservesAllowlistedTextAndLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		clean := rapid.StringMatching(`[a-zA-Z0-9-]{0,64}`).Draw(t, "clean")
		if got := Sanitize(clean); got != clean {
			t.Fatalf("Sanitize(%q) = %q, want unchanged", clean, got)
		}

		s := anyString().Draw(t, "s")
		units := 0
		for range s {
			units++
		}
		if got := len(Sanitize(s)); got != units {
			t.Fatalf("len(Sanitize(%q)) = %d, want %d", s, got, units)
		}
	})
}
