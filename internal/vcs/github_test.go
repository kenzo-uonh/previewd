package vcs

import "testing"

// Fail closed: only admin, maintain and write are write access; only a head
// in the base repository, opened by such an account, is trusted.
func TestTrusted(t *testing.T) {
	same := PRState{Open: true, HeadRepo: "acme/app", Opener: Account{Login: "opener", ID: 4242}}
	for _, p := range []string{"admin", "maintain", "write"} {
		same.OpenerPermission = p
		if !Trusted(same, "acme/app") {
			t.Errorf("%s: not trusted", p)
		}
	}
	for _, p := range []string{"triage", "read", "none", "", "Write", "ADMIN", "owner"} {
		same.OpenerPermission = p
		if Trusted(same, "acme/app") {
			t.Errorf("%q: trusted", p)
		}
	}
	for name, pr := range map[string]PRState{
		"fork":              {HeadRepo: "outside/app", OpenerPermission: "admin"},
		"deleted head repo": {HeadRepo: "", OpenerPermission: "admin"},
		"case differs":      {HeadRepo: "Acme/App", OpenerPermission: "admin"},
	} {
		if Trusted(pr, "acme/app") {
			t.Errorf("%s: trusted", name)
		}
	}
	if Trusted(PRState{OpenerPermission: "admin"}, "") {
		t.Error("empty base and head repositories: trusted")
	}
}
