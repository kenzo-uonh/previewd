package validate

import (
	"strings"
	"testing"
)

func TestForgejoRepoFullName(t *testing.T) {
	for _, ok := range []string{
		"acme/app", "a_b/c.d-e", "john.doe/my_repo", "Org-1/App.v2", "x/.hidden", "x/-dash",
		strings.Repeat("a", 39) + "/" + strings.Repeat("r", 100),
	} {
		if err := ForgejoRepoFullName(ok); err != nil {
			t.Errorf("ForgejoRepoFullName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "app", "/app", "acme/", "acme/app/x", "acme/.", "acme/..", "acme/app.git", "acme/app.wiki",
		"-acme/app", "_acme/app", "acme-/app", "ac..me/app", "ac-_me/app", "acme/ap p", "acme/app\n",
		"acme/a%2Fb", "acme\\app", "acme/ápp",
		strings.Repeat("a", 41) + "/app", "acme/" + strings.Repeat("r", 101),
		// Within Forgejo's limits, beyond the 140 bytes the queue keeps.
		strings.Repeat("a", 40) + "/" + strings.Repeat("r", 100),
	} {
		if err := ForgejoRepoFullName(bad); err == nil {
			t.Errorf("ForgejoRepoFullName(%q) accepted", bad)
		}
	}
}

func TestForgejoUsername(t *testing.T) {
	for _, ok := range []string{"lead-dev", "john.doe", "a_b", "A1", "x", strings.Repeat("a", 39)} {
		if err := ForgejoUsername(ok); err != nil {
			t.Errorf("ForgejoUsername(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "-x", ".x", "_x", "x-", "x.", "x__y", "x.-y", "x y", "x/y", "x\n", "x@y",
		// Forgejo's limit is 40; the audit trail keeps 39.
		strings.Repeat("a", 40),
	} {
		if err := ForgejoUsername(bad); err == nil {
			t.Errorf("ForgejoUsername(%q) accepted", bad)
		}
	}
}

func TestForgejoURL(t *testing.T) {
	if got, err := ForgejoURL("https://forge.corp:3000/"); err != nil || got != "https://forge.corp:3000" {
		t.Errorf("ForgejoURL = %q, %v", got, err)
	}
	for _, bad := range []string{"", "http://forge.corp", "https://forge.corp/git", "https://u@forge.corp", "https://forge.corp?x=1"} {
		if _, err := ForgejoURL(bad); err == nil {
			t.Errorf("ForgejoURL(%q) accepted", bad)
		}
	}
}

func TestParseForgejoApprovers(t *testing.T) {
	got, err := ParseForgejoApprovers("acme/app:lead.dev#7,acme/app:second_one#8,john.doe/x:john.doe#9")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["acme/app"]) != 2 || got["acme/app"][0] != (Approver{Login: "lead.dev", ID: 7}) || got["john.doe/x"][0].ID != 9 {
		t.Errorf("approvers = %+v", got)
	}
	for _, bad := range []string{
		"acme/app:lead.dev",                          // no ID
		"acme/app:lead..dev#7",                       // not a Forgejo username
		"acme/app.git:lead#7",                        // not a Forgejo repository
		"acme/app:" + strings.Repeat("a", 40) + "#7", // beyond what the audit trail keeps
		"acme/app:a#7,acme/app:b#7",                  // the same account twice
	} {
		if _, err := ParseForgejoApprovers(bad); err == nil {
			t.Errorf("ParseForgejoApprovers(%q) accepted", bad)
		}
	}
}

func TestEventUUID(t *testing.T) {
	if got, err := EventUUID("8F14E45F-CEEA-467A-9575-4C5B0B5B2E6C"); err != nil || got != "8f14e45f-ceea-467a-9575-4c5b0b5b2e6c" {
		t.Errorf("EventUUID = %q, %v", got, err)
	}
	for _, bad := range []string{"", "8f14e45fceea467a95754c5b0b5b2e6c", "8f14e45f-ceea-467a-9575-4c5b0b5b2e6", "{8f14e45f-ceea-467a-9575-4c5b0b5b2e6c}"} {
		if _, err := EventUUID(bad); err == nil {
			t.Errorf("EventUUID(%q) accepted", bad)
		}
	}
}
