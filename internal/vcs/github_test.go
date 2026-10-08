package vcs

import "testing"

// Fail closed: only admin, maintain and write are write access; only a head
// in the base repository, opened by such an account, is trusted.
func TestTrusted(t *testing.T) {
	same := PRState{Open: true, HeadRepo: "acme/app", OpenerLogin: "opener"}
	for _, p := range []string{"admin", "maintain", "write"} {
		if !Trusted(same, "acme/app", p) {
			t.Errorf("%s: not trusted", p)
		}
	}
	for _, p := range []string{"triage", "read", "none", "", "Write", "ADMIN", "owner"} {
		if Trusted(same, "acme/app", p) {
			t.Errorf("%q: trusted", p)
		}
	}
	for name, pr := range map[string]PRState{
		"fork":              {HeadRepo: "outside/app"},
		"deleted head repo": {HeadRepo: ""},
		"case differs":      {HeadRepo: "Acme/App"},
	} {
		if Trusted(pr, "acme/app", "admin") {
			t.Errorf("%s: trusted", name)
		}
	}
	if Trusted(PRState{}, "", "admin") {
		t.Error("empty base and head repositories: trusted")
	}
}
