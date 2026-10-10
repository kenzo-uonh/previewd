package validate

import (
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// Quote is how untrusted text reaches an error or a log value: no control
// character survives, and the result is bounded whatever the input size.
func TestQuoteEscapesAndBounds(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain":        {"pull_request", `"pull_request"`},
		"empty":        {"", `""`},
		"line breaks":  {"a\nb\rc", `"a\nb\rc"`},
		"forged entry": {"x\n{\"level\":\"ERROR\"}", `"x\n{\"level\":\"ERROR\"}"`},
		"at the bound": {strings.Repeat("a", maxQuotedLen), `"` + strings.Repeat("a", maxQuotedLen) + `"`},
		"over it":      {strings.Repeat("a", maxQuotedLen+1), `"` + strings.Repeat("a", maxQuotedLen) + `"...(65 bytes)`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := Quote(tc.in); got != tc.want {
				t.Fatalf("Quote(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}

	huge := strings.Repeat("\n\x00\u2028\xff", 1<<16)
	got := Quote(huge)
	if len(got) > 4*maxQuotedLen+32 {
		t.Fatalf("Quote of %d bytes is %d bytes", len(huge), len(got))
	}
	for _, r := range got {
		if unicode.IsControl(r) || r == '\u2028' {
			t.Fatalf("Quote output holds %U: %s", r, got)
		}
	}
	if !strings.HasSuffix(got, "...("+strconv.Itoa(len(huge))+" bytes)") {
		t.Fatalf("Quote output does not report the input size: %s", got)
	}
}
