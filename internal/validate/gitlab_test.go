package validate

import (
	"strings"
	"testing"
	"time"
)

func TestGitLabProjectPath(t *testing.T) {
	for _, ok := range []string{"acme/app", "acme/sub/app", "a_b/c.d-e", strings.Repeat("a/", 19) + "app"} {
		if err := GitLabProjectPath(ok); err != nil {
			t.Errorf("GitLabProjectPath(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "app", "/acme/app", "acme/app/", "acme//app", "acme/../app", "acme/./app", "-acme/app", "acme/.app",
		"acme/app.git", "acme/app.atom", "acme/app.", "acme/ap p", "acme/app\n", "acme/a%2Fb", "acme\\app",
		strings.Repeat("a/", 22) + "app", strings.Repeat("a", 256) + "/app",
	} {
		if err := GitLabProjectPath(bad); err == nil {
			t.Errorf("GitLabProjectPath(%q) accepted", bad)
		}
	}
}

func TestGitLabUsername(t *testing.T) {
	for _, ok := range []string{"lead-dev", "john.doe", "_svc", "A1"} {
		if err := GitLabUsername(ok); err != nil {
			t.Errorf("GitLabUsername(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "x y", "x/y", "x.git", "x.atom", "x\n", strings.Repeat("a", 256)} {
		if err := GitLabUsername(bad); err == nil {
			t.Errorf("GitLabUsername(%q) accepted", bad)
		}
	}
}

func TestGitLabProjectID(t *testing.T) {
	for _, ok := range []string{"1", "42", "9223372036854775807"} {
		if err := GitLabProjectID(ok); err != nil {
			t.Errorf("GitLabProjectID(%q) = %v, want nil", ok, err)
		}
	}
	// A path instead of the numeric ID would be URL-encoded by a careless
	// caller; an ID with a sign, a leading zero or a slash is refused.
	for _, bad := range []string{"", "0", "-1", "+1", "01", "1/2", "1.5", "acme/app", "9223372036854775808", " 1"} {
		if err := GitLabProjectID(bad); err == nil {
			t.Errorf("GitLabProjectID(%q) accepted", bad)
		}
	}
}

func TestMergeRequestIID(t *testing.T) {
	if n, err := MergeRequestIID("7"); err != nil || n != 7 {
		t.Errorf("MergeRequestIID(7) = %d, %v", n, err)
	}
	for _, bad := range []string{"", "0", "-7", "07", "7.0", "4294967296", "x"} {
		if _, err := MergeRequestIID(bad); err == nil {
			t.Errorf("MergeRequestIID(%q) accepted", bad)
		}
	}
}

func TestGitLabTimestamp(t *testing.T) {
	want := time.Date(2026, 10, 20, 10, 30, 5, 0, time.UTC)
	for _, ok := range []string{"2026-10-20 10:30:05 UTC", "2026-10-20T10:30:05Z", "2026-10-20 12:30:05 +0200", "2026-10-20T10:30:05.000Z"} {
		got, err := GitLabTimestamp(ok)
		if err != nil || !got.Equal(want) || got.Location() != time.UTC {
			t.Errorf("GitLabTimestamp(%q) = %v, %v; want %v", ok, got, err, want)
		}
	}
	for _, bad := range []string{"", "yesterday", "2026-10-20", "1970-01-01 00:00:00 UTC", strings.Repeat("2", 40)} {
		if _, err := GitLabTimestamp(bad); err == nil {
			t.Errorf("GitLabTimestamp(%q) accepted", bad)
		}
	}
}

func TestGitLabURL(t *testing.T) {
	got, err := GitLabURL("https://gitlab.internal.corp:8443/")
	if err != nil || got != "https://gitlab.internal.corp:8443" {
		t.Errorf("GitLabURL = %q, %v", got, err)
	}
	for _, bad := range []string{"", "http://gitlab.corp", "https://u:p@gitlab.corp", "https://gitlab.corp/sub", "https://gitlab.corp?x=1", "gitlab.corp"} {
		if _, err := GitLabURL(bad); err == nil {
			t.Errorf("GitLabURL(%q) accepted", bad)
		}
	}
}

func TestParseGitLabApprovers(t *testing.T) {
	got, err := ParseGitLabApprovers("acme/sub/app:lead.dev#7,acme/sub/app:other#8,acme/web:lead.dev#7")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["acme/sub/app"]) != 2 || got["acme/sub/app"][0] != (Approver{Login: "lead.dev", ID: 7}) || len(got["acme/web"]) != 1 {
		t.Errorf("approvers = %+v", got)
	}
	for _, bad := range []string{
		"acme/app:lead", "acme/app:lead#0", "acme/app:lead#07", "app:lead#7", "acme/app:-x#7",
		"acme/app:lead#7,acme/app:other#7", "acme/app:lead#7,", ",",
	} {
		if _, err := ParseGitLabApprovers(bad); err == nil {
			t.Errorf("ParseGitLabApprovers(%q) accepted", bad)
		}
	}
	// The GitHub parser keeps refusing a GitLab nested path: one grammar per forge.
	if _, err := ParseApprovers("acme/sub/app:lead#7"); err == nil {
		t.Error("ParseApprovers accepted a nested path")
	}
}

func TestGitLabEventUUID(t *testing.T) {
	for in, want := range map[string]string{
		"5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b00": "5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b00",
		"5D6D2E4A-6F5C-4A39-9A3E-3F0F3C2A1B00": "5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b00",
	} {
		if got, err := GitLabEventUUID(in); err != nil || got != want {
			t.Errorf("GitLabEventUUID(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "5d6d2e4a6f5c4a399a3e3f0f3c2a1b00", "{5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b00}", "urn:uuid:5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b00",
		"5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b0", "5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1b000", "5d6d2e4a-6f5c-4a39-9a3e-3f0f3c2a1bzz",
		"5d6d2e4a_6f5c_4a39_9a3e_3f0f3c2a1b00",
	} {
		if got, err := GitLabEventUUID(bad); err == nil {
			t.Errorf("GitLabEventUUID(%q) accepted as %q", bad, got)
		}
	}
}

// SeqAt puts an instant on the scale of a delivery's Seq: GitHub's UUIDv1
// ticks, so an environment's intents compare across a change of forge.
func TestSeqAtIsTheDeliverySequenceScale(t *testing.T) {
	d, err := ParseDeliveryID("72d3162e-cc78-11e3-81ab-4c9367dc0958")
	if err != nil {
		t.Fatal(err)
	}
	if got := SeqAt(d.Time); got != d.Seq {
		t.Errorf("SeqAt(%v) = %d, want %d", d.Time, got, d.Seq)
	}
	if a, b := SeqAt(d.Time), SeqAt(d.Time.Add(100*time.Nanosecond)); b != a+1 {
		t.Errorf("one tick apart: %d, %d", a, b)
	}
}

// The store keeps a project path in 140 bytes and a login in 39: what it
// cannot hold is refused where it enters, never as a storage error later.
func TestGitLabStoreLimits(t *testing.T) {
	long := strings.Repeat("a", 69) + "/" + strings.Repeat("b", 70) // 140 bytes
	if err := GitLabProjectPath(long); err != nil {
		t.Errorf("a 140-byte path refused: %v", err)
	}
	if err := GitLabProjectPath(long + "c"); err == nil {
		t.Error("a 141-byte path accepted")
	}
	if _, err := ParseGitLabApprovers("acme/app:" + strings.Repeat("u", 39) + "#7"); err != nil {
		t.Errorf("a 39-byte login refused: %v", err)
	}
	if _, err := ParseGitLabApprovers("acme/app:" + strings.Repeat("u", 40) + "#7"); err == nil {
		t.Error("a 40-byte approver login accepted")
	}
	// An event's sender is not stored: a long username is a valid username.
	if err := GitLabUsername(strings.Repeat("u", 40)); err != nil {
		t.Errorf("a 40-byte username refused: %v", err)
	}
}
