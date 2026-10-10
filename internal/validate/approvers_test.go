package validate

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestParseApprovers(t *testing.T) {
	got, err := ParseApprovers("acme/shop:lead-dev#7,acme/shop:sec_ops#8,acme/api:lead-dev#7")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]Approver{
		"acme/shop": {{Login: "lead-dev", ID: 7}, {Login: "sec_ops", ID: 8}},
		"acme/api":  {{Login: "lead-dev", ID: 7}},
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := ParseApprovers(""); err != nil || len(got) != 0 {
		t.Fatalf("empty value = %v, %v; want no approver", got, err)
	}
}

// Fail closed: one malformed entry refuses the whole list.
func TestParseApproversRefusesMalformedEntries(t *testing.T) {
	for _, bad := range []string{
		"acme/shop:lead-dev",                       // no #id: a login alone is not an identity
		"acme/shop:lead-dev#",                      // empty id
		"acme/shop:lead-dev#0",                     // zero id
		"acme/shop:lead-dev#-7",                    // negative id
		"acme/shop:lead-dev#07",                    // non-canonical id
		"acme/shop:lead-dev#7x",                    // trailing garbage
		"acme/shop:lead-dev#99999999999999999999",  // overflow
		"lead-dev#7",                               // no repository
		"acme:lead-dev#7",                          // not owner/repo
		"acme/shop:-lead#7",                        // invalid login
		"acme/shop:#7",                             // empty login
		"acme/shop:lead-dev#7,",                    // empty entry
		",acme/shop:lead-dev#7",                    // empty entry
		"acme/shop:lead-dev#7, acme/api:x#8",       // space before an entry
		"acme/shop:lead-dev#7,acme/shop:renamed#7", // the same account twice
		"acme/shop:lead#dev#7",                     // two separators
		strings.Repeat("a", 64<<10+1),              // too long
	} {
		if got, err := ParseApprovers(bad); err == nil {
			t.Errorf("ParseApprovers(%.60q) = %v, want an error", bad, got)
		}
	}
}

// Total function: ParseApprovers never panics; whatever it accepts is a set
// of valid, distinct (repository, ID) approvers that formats back to an
// equivalent value.
func FuzzParseApprovers(f *testing.F) {
	f.Add("acme/shop:lead-dev#7,acme/api:sec_ops#8")
	f.Add("acme/shop:lead-dev")
	f.Add("acme/shop:lead-dev#7,acme/shop:x#7")
	f.Add(",")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseApprovers(s)
		if err != nil {
			if got != nil {
				t.Fatalf("refused value returned %v", got)
			}
			return
		}
		var entries []string
		for repo, approvers := range got {
			if RepoFullName(repo) != nil {
				t.Fatalf("accepted repository %q", repo)
			}
			seen := map[int64]bool{}
			for _, a := range approvers {
				if Login(a.Login) != nil || a.ID <= 0 || seen[a.ID] {
					t.Fatalf("accepted approver %+v of %s", a, repo)
				}
				seen[a.ID] = true
				entries = append(entries, fmt.Sprintf("%s:%s#%d", repo, a.Login, a.ID))
			}
		}
		again, err := ParseApprovers(strings.Join(entries, ","))
		if err != nil || !maps.EqualFunc(again, got, slices.Equal) {
			t.Fatalf("formatted %v back to %v, %v", got, again, err)
		}
	})
}
