package validate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Reference values computed with Python's uuid module (UUID.time).
func TestParseDeliveryIDKnownVectors(t *testing.T) {
	for _, tc := range []struct {
		in   string
		seq  int64
		when time.Time
	}{
		// A GitHub delivery GUID from GitHub's own documentation.
		{"72d3162e-cc78-11e3-81ab-4c9367dc0958", 136177231445825070, time.Date(2014, 4, 25, 12, 52, 24, 582507000, time.UTC)},
		{"6A3BD9A0-A4C5-11F1-8000-000000000001", 140074231223015840, time.Date(2026, 8, 30, 22, 52, 2, 301584000, time.UTC)},
	} {
		d, err := ParseDeliveryID(tc.in)
		if err != nil {
			t.Fatalf("ParseDeliveryID(%q): %v", tc.in, err)
		}
		if d.ID != strings.ToLower(tc.in) || d.Seq != tc.seq || !d.Time.Equal(tc.when) {
			t.Fatalf("ParseDeliveryID(%q) = %+v, want seq %d at %v", tc.in, d, tc.seq, tc.when)
		}
	}
}

func TestParseDeliveryIDRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":              "",
		"v4":                 "3f1c6b2e-9a7d-4c1b-8e2f-0a1b2c3d4e5f",
		"v6":                 "1f0a4c6e-2b3d-6e4f-8a1b-0c2d3e4f5a6b",
		"v7":                 "01890a5d-ac96-774b-bcce-b302099a8057",
		"nil uuid":           "00000000-0000-0000-0000-000000000000",
		"ncs variant":        "72d3162e-cc78-11e3-41ab-4c9367dc0958",
		"microsoft variant":  "72d3162e-cc78-11e3-c1ab-4c9367dc0958",
		"no hyphens":         "72d3162ecc7811e381ab4c9367dc0958",
		"braces":             "{72d3162e-cc78-11e3-81ab-4c9367dc0958}",
		"urn":                "urn:uuid:72d3162e-cc78-11e3-81ab-4c9367dc0958",
		"hyphen moved":       "72d3162ec-c78-11e3-81ab-4c9367dc0958",
		"non hex":            "72d3162g-cc78-11e3-81ab-4c9367dc0958",
		"trailing space":     "72d3162e-cc78-11e3-81ab-4c9367dc095 ",
		"before unix epoch":  "00000000-0000-1000-8000-000000000000",
		"one tick pre 1970":  "13813fff-1dd2-11b2-8000-000000000000",
		"unicode lookalike":  "72d3162e-cc78-11e3-81ab-4c9367dc095０",
		"newline":            "72d3162e-cc78-11e3-81ab-4c9367dc095\n",
		"exactly unix epoch": "13814000-1dd2-11b2-8000-000000000000",
	} {
		if _, err := ParseDeliveryID(in); !errors.Is(err, ErrDelivery) {
			t.Errorf("%s: ParseDeliveryID(%q) = %v, want ErrDelivery", name, in, err)
		}
	}
}

// formatV1 builds a UUIDv1 from its fields, independently of the parser.
func formatV1(ticks uint64, clockSeq uint16, node uint64, upper bool) string {
	s := fmt.Sprintf("%08x-%04x-1%03x-%04x-%012x",
		ticks&0xffffffff, (ticks>>32)&0xffff, (ticks>>48)&0xfff,
		0x8000|uint64(clockSeq&0x3fff), node&0xffffffffffff)
	if upper {
		return strings.ToUpper(s)
	}
	return s
}

// Any UUIDv1 after 1970 round-trips its timestamp; order of Seq is the
// order of the timestamps; the ID is canonical lower case.
func TestParseDeliveryIDRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ticks := rapid.Uint64Range(uuidEpochOffset+1, 1<<60-1).Draw(t, "ticks")
		clockSeq := rapid.Uint16().Draw(t, "clock seq")
		node := rapid.Uint64().Draw(t, "node")
		upper := rapid.Bool().Draw(t, "upper")
		s := formatV1(ticks, clockSeq, node, upper)

		d, err := ParseDeliveryID(s)
		if err != nil {
			t.Fatalf("ParseDeliveryID(%q): %v", s, err)
		}
		if uint64(d.Seq) != ticks || d.ID != strings.ToLower(s) {
			t.Fatalf("ParseDeliveryID(%q) = %+v, want seq %d", s, d, ticks)
		}
		wantUnix := int64(ticks - uuidEpochOffset)
		if got := d.Time.Unix()*1e7 + int64(d.Time.Nanosecond()/100); got != wantUnix {
			t.Fatalf("time %v is %d ticks after 1970, want %d", d.Time, got, wantUnix)
		}

		other := rapid.Uint64Range(uuidEpochOffset+1, 1<<60-1).Draw(t, "other ticks")
		o, err := ParseDeliveryID(formatV1(other, clockSeq, node, false))
		if err != nil {
			t.Fatal(err)
		}
		if (ticks < other) != (d.Seq < o.Seq) || (ticks < other) != d.Time.Before(o.Time) {
			t.Fatalf("order of %d and %d not preserved", ticks, other)
		}
	})
}

// Changing the version nibble to anything but 1 is refused.
func TestParseDeliveryIDRefusesOtherVersions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := []byte(formatV1(rapid.Uint64Range(uuidEpochOffset+1, 1<<60-1).Draw(t, "ticks"), 0, 0, false))
		v := rapid.SampledFrom([]byte("023456789abcdef")).Draw(t, "version")
		s[14] = v
		if _, err := ParseDeliveryID(string(s)); !errors.Is(err, ErrDelivery) {
			t.Fatalf("version %c accepted: %s", v, s)
		}
	})
}

func FuzzParseDeliveryID(f *testing.F) {
	for _, seed := range []string{
		"72d3162e-cc78-11e3-81ab-4c9367dc0958",
		"3f1c6b2e-9a7d-4c1b-8e2f-0a1b2c3d4e5f",
		"",
		"13814000-1dd2-11b2-8000-000000000000",
		"ffffffff-ffff-1fff-bfff-ffffffffffff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDeliveryID(s)
		if err != nil {
			if !errors.Is(err, ErrDelivery) {
				t.Fatalf("error %v is not ErrDelivery", err)
			}
			return
		}
		if len(d.ID) != 36 || d.ID != strings.ToLower(s) || d.ID[14] != '1' || !strings.ContainsRune("89ab", rune(d.ID[19])) {
			t.Fatalf("accepted non-canonical %q as %+v", s, d)
		}
		if d.Seq <= uuidEpochOffset || d.Time.Before(time.Unix(0, 0)) {
			t.Fatalf("accepted pre-1970 %q as %+v", s, d)
		}
		// The fields re-encode to the same ID.
		ticks := uint64(d.Seq)
		re := fmt.Sprintf("%08x-%04x-1%03x-%s", ticks&0xffffffff, (ticks>>32)&0xffff, (ticks>>48)&0xfff, d.ID[19:])
		if re != d.ID {
			t.Fatalf("re-encoded %q, parsed %q", re, d.ID)
		}
	})
}
