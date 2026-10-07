// Package textutil makes untrusted text safe to use as a single path
// component, shell word or identifier.
package textutil

import "strings"

// Sanitize maps s onto the allowlist [a-zA-Z0-9-]: every other rune,
// including each byte of invalid UTF-8, becomes '-'. The result cannot hold a
// path separator, a dot segment, whitespace, a quote or a shell
// metacharacter. Sanitize is idempotent.
func Sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if allowed(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func allowed(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
}
