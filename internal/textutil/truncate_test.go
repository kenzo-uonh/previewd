package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// Truncate: valid UTF-8, bounded, a prefix of the cleaned input, unchanged
// when short enough.
func TestTruncateIsBoundedValidPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := anyString().Draw(t, "s")
		n := rapid.IntRange(0, 64).Draw(t, "max")
		got := Truncate(s, n)
		clean := strings.ToValidUTF8(s, "�")

		if !utf8.ValidString(got) {
			t.Fatalf("Truncate(%q, %d) = %q is not valid UTF-8", s, n, got)
		}
		if len(clean) <= n {
			if got != clean {
				t.Fatalf("Truncate(%q, %d) = %q, want it unchanged", s, n, got)
			}
			return
		}
		body, ok := strings.CutSuffix(got, TruncationMark)
		if !ok || len(body) > n || !strings.HasPrefix(clean, body) {
			t.Fatalf("Truncate(%q, %d) = %q: want a prefix of at most %d bytes plus the mark", s, n, got, n)
		}
		// The cut is at the last rune boundary that fits.
		if next, size := utf8.DecodeRuneInString(clean[len(body):]); next != utf8.RuneError && len(body)+size <= n {
			t.Fatalf("Truncate(%q, %d) = %q cut too early", s, n, got)
		}
	})
}

func TestTruncateExamples(t *testing.T) {
	for _, tc := range []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"eleven char", 10, "eleven cha…"},
		{"ééé", 3, "é…"},      // never splits a rune
		{"a\xffb", 10, "a�b"}, // invalid byte replaced
		{"abc", 0, "…"},
		{"abc", -1, "…"},
	} {
		if got := Truncate(tc.in, tc.max); got != tc.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}
