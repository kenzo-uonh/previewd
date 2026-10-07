package textutil

import (
	"strings"
	"unicode/utf8"
)

// TruncationMark ends a truncated string.
const TruncationMark = "…"

// Truncate bounds untrusted text for an error or a log line: invalid UTF-8
// becomes U+FFFD, and a result longer than maxBytes is cut at a rune
// boundary and ends with TruncationMark. The result is valid UTF-8 and at
// most maxBytes+len(TruncationMark) bytes. Quote the result (%q) where it
// joins other text, so control characters stay visible.
func Truncate(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= maxBytes {
		return s
	}
	cut := max(maxBytes, 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + TruncationMark
}
