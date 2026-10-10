package validate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

const validPayload = `{
  "action": "opened",
  "number": 42,
  "pull_request": {
    "number": 42,
    "head": {"ref": "feature/login", "sha": "0123456789abcdef0123456789abcdef01234567", "repo": {"full_name": "fork/shop"}},
    "user": {"login": "octo-cat", "id": 4242},
    "updated_at": "2026-10-08T12:00:00Z"
  },
  "repository": {"full_name": "acme/shop", "clone_url": "https://ghes.example/acme/shop.git"},
  "sender": {"login": "octo-cat", "id": 4242}
}`

// Total function + rejection: VerifySignature never panics, and it accepts
// exactly one header per (secret, body) — the exact lowercase HMAC — and
// nothing at all without a secret or above the size cap.
func FuzzVerifySignature(f *testing.F) {
	secret, body := []byte("s3cret"), []byte(validPayload)
	good := sign(secret, body)
	f.Add(secret, body, good)
	f.Add([]byte{}, body, sign(nil, body))
	f.Add(secret, body, strings.ToUpper(good))
	f.Add(secret, body, strings.TrimPrefix(good, signaturePrefix))
	f.Add(secret, body, good[:len(good)-1])
	f.Add(secret, body, good+"0")
	f.Add(secret, body, "sha1="+good[len(signaturePrefix):])
	f.Add(secret, []byte{}, sign(secret, nil))

	f.Fuzz(func(t *testing.T, secret, body []byte, header string) {
		err := VerifySignature(secret, body, header)
		accept := len(secret) > 0 && len(body) <= MaxPayloadBytes && header == sign(secret, body)
		if accept && err != nil {
			t.Fatalf("exact signature rejected: %v", err)
		}
		if !accept && err == nil {
			t.Fatalf("accepted secret=%q body=%q header=%q", secret, body, header)
		}
		if err != nil && !errors.Is(err, ErrSignature) {
			t.Fatalf("rejection is not ErrSignature: %v", err)
		}
	})
}

// Total function + rejection: ParsePullRequest never panics; whatever it
// returns without ErrPayload satisfies every validator independently.
func FuzzParsePullRequest(f *testing.F) {
	f.Add([]byte(validPayload))
	f.Add([]byte(strings.Replace(validPayload, `"opened"`, `"closed"`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `"opened"`, `"labeled"`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `42`, `-1`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `42`, `4294967296`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `feature/login`, `../../x`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `{"full_name": "fork/shop"}`, `null`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `octo-cat`, `-octo`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `4242`, `0`, 1)))
	f.Add([]byte(strings.Replace(validPayload, `"opened"`, `"labeled"`, 1)[:len(validPayload)-1] + `,"label":{"name":"previewd-approved"}}`))
	f.Add([]byte(strings.Replace(validPayload, `2026-10-08T12:00:00Z`, `2026-10-08 12:00`, 1)))
	f.Add([]byte(`{"action":"opened"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(validPayload + `{}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		pr, err := ParsePullRequest(body)
		switch {
		case err == nil, errors.Is(err, ErrIgnoredAction):
		case errors.Is(err, ErrPayload):
			if pr != (PullRequest{}) {
				t.Fatalf("rejected payload returned data: %+v", pr)
			}
			return
		default:
			t.Fatalf("error is neither ErrPayload nor ErrIgnoredAction: %v", err)
		}

		if len(body) > MaxPayloadBytes {
			t.Fatalf("accepted %d-byte body", len(body))
		}
		if pr.Number == 0 {
			t.Fatal("accepted PR number 0")
		}
		if pr.OpenerID <= 0 || pr.SenderID <= 0 {
			t.Fatalf("accepted opener id %d, sender id %d", pr.OpenerID, pr.SenderID)
		}
		if pr.UpdatedAt.Unix() <= 0 || pr.UpdatedAt.Location() != time.UTC {
			t.Fatalf("accepted updated_at %v", pr.UpdatedAt)
		}
		labeled := pr.Action == ActionLabeled || pr.Action == ActionUnlabeled
		if err == nil && labeled != (pr.Label != "") {
			t.Fatalf("action %q with label %q", pr.Action, pr.Label)
		}
		if pr.Label != "" {
			if err := LabelName(pr.Label); err != nil {
				t.Fatalf("accepted invalid label: %v", err)
			}
		}
		if pr.HeadRepo != "" {
			if err := RepoFullName(pr.HeadRepo); err != nil {
				t.Fatalf("accepted invalid head repo: %v", err)
			}
		}
		for name, check := range map[string]error{
			"repo": RepoFullName(pr.Repo), "ref": GitRef(pr.HeadRef), "sha": CommitSHA(pr.HeadSHA), "clone": cloneURL(pr.CloneURL),
			"opener": Login(pr.OpenerLogin), "sender": Login(pr.SenderLogin),
		} {
			if check != nil {
				t.Fatalf("accepted invalid %s: %v", name, check)
			}
		}
		acted := pr.Action == ActionOpened || pr.Action == ActionReopened || pr.Action == ActionSynchronize ||
			pr.Action == ActionClosed || labeled
		if acted != (err == nil) {
			t.Fatalf("action %q returned err=%v", pr.Action, err)
		}
	})
}

func TestParsePullRequestAcceptsValidPayload(t *testing.T) {
	pr, err := ParsePullRequest([]byte(validPayload))
	if err != nil {
		t.Fatalf("ParsePullRequest: %v", err)
	}
	want := PullRequest{
		Action: ActionOpened, Number: 42, Repo: "acme/shop", HeadRef: "feature/login",
		HeadSHA: "0123456789abcdef0123456789abcdef01234567", CloneURL: "https://ghes.example/acme/shop.git",
		HeadRepo: "fork/shop", OpenerLogin: "octo-cat", OpenerID: 4242,
		UpdatedAt: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC), SenderLogin: "octo-cat", SenderID: 4242,
	}
	if pr != want {
		t.Fatalf("got %+v, want %+v", pr, want)
	}
}

// labeled and unlabeled carry a validated label name; without one they are
// refused, never treated as another label.
func TestParsePullRequestLabel(t *testing.T) {
	labeled := func(action, label string) []byte {
		body := strings.Replace(validPayload, `"opened"`, `"`+action+`"`, 1)
		return []byte(strings.TrimSuffix(body, "}") + label + "}")
	}
	for _, action := range []string{ActionLabeled, ActionUnlabeled} {
		pr, err := ParsePullRequest(labeled(action, `,"label":{"name":"previewd-approved"}`))
		if err != nil || pr.Label != "previewd-approved" {
			t.Fatalf("%s = %+v, %v", action, pr, err)
		}
		for name, label := range map[string]string{
			"no label":      ``,
			"no name":       `,"label":{}`,
			"empty name":    `,"label":{"name":""}`,
			"long name":     `,"label":{"name":"` + strings.Repeat("l", 51) + `"}`,
			"control char":  `,"label":{"name":"approved\u0007"}`,
			"numeric name":  `,"label":{"name":7}`,
			"label is null": `,"label":null`,
		} {
			if _, err := ParsePullRequest(labeled(action, label)); !errors.Is(err, ErrPayload) {
				t.Errorf("%s with %s: %v, want ErrPayload", action, name, err)
			}
		}
	}
}

// A deleted fork: head.repo is null. Accepted with no head repository,
// which the authorizer can only judge untrusted.
func TestParsePullRequestDeletedHeadRepo(t *testing.T) {
	pr, err := ParsePullRequest([]byte(strings.Replace(validPayload, `{"full_name": "fork/shop"}`, `null`, 1)))
	if err != nil || pr.HeadRepo != "" {
		t.Fatalf("null head.repo = %+v, %v; want accepted with an empty head repository", pr, err)
	}
}

// Every required field, removed, rejects the payload.
func TestParsePullRequestRejectsMissingFields(t *testing.T) {
	paths := [][]string{
		{"action"}, {"number"}, {"pull_request"}, {"pull_request", "head"}, {"pull_request", "head", "ref"},
		{"pull_request", "head", "sha"}, {"pull_request", "head", "repo", "full_name"}, {"pull_request", "user"},
		{"pull_request", "user", "login"}, {"pull_request", "user", "id"}, {"pull_request", "updated_at"},
		{"sender"}, {"sender", "login"}, {"sender", "id"},
		{"repository"}, {"repository", "full_name"}, {"repository", "clone_url"},
	}
	for _, path := range paths {
		var doc map[string]any
		if err := json.Unmarshal([]byte(validPayload), &doc); err != nil {
			t.Fatal(err)
		}
		parent := doc
		for _, key := range path[:len(path)-1] {
			parent = parent[key].(map[string]any)
		}
		delete(parent, path[len(path)-1])
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParsePullRequest(body); !errors.Is(err, ErrPayload) {
			t.Errorf("missing %s: err = %v, want ErrPayload", strings.Join(path, "."), err)
		}
	}
}

func TestParsePullRequestRejectsInvalidFields(t *testing.T) {
	for name, edit := range map[string][2]string{
		"zero number":      {`42`, `0`},
		"string number":    {`42`, `"42"`},
		"float number":     {`42`, `42.5`},
		"traversal ref":    {`feature/login`, `../escape`},
		"control in ref":   {`feature/login`, `feat\u0000x`},
		"short sha":        {`0123456789abcdef0123456789abcdef01234567`, `0123456`},
		"uppercase sha":    {`0123456789abcdef0123456789abcdef01234567`, `0123456789ABCDEF0123456789ABCDEF01234567`},
		"bad repo":         {`acme/shop`, `acme/../shop`},
		"credentials url":  {`https://ghes.example`, `https://user:pass@ghes.example`},
		"relative url":     {`https://ghes.example/acme/shop.git`, `acme/shop.git`},
		"space in url":     {`https://ghes.example/acme/shop.git`, `https://ghes.example/a b.git`},
		"trailing garbage": {`"https://ghes.example/acme/shop.git"}`, `"https://ghes.example/acme/shop.git"}} x`},
		"bad head repo":    {`fork/shop`, `fork/../shop`},
		"hyphen login":     {`octo-cat`, `-octocat`},
		"long login":       {`octo-cat`, strings.Repeat("o", 40)},
		"slash login":      {`octo-cat`, `octo/cat`},
		"zero opener id":   {`4242`, `0`},
		"negative id":      {`4242`, `-4242`},
		"string id":        {`4242`, `"4242"`},
		"local timestamp":  {`2026-10-08T12:00:00Z`, `2026-10-08T12:00:00`},
		"epoch timestamp":  {`2026-10-08T12:00:00Z`, `1970-01-01T00:00:00Z`},
		"numeric time":     {`"2026-10-08T12:00:00Z"`, `1791460800`},
		"bad sender":       {`"sender": {"login": "octo-cat"`, `"sender": {"login": "octo cat"`},
	} {
		body := strings.Replace(validPayload, edit[0], edit[1], 1)
		if body == validPayload {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := ParsePullRequest([]byte(body)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: err = %v, want ErrPayload", name, err)
		}
	}
}

func TestParsePullRequestRejectsOversizedBody(t *testing.T) {
	body := []byte(validPayload + strings.Repeat(" ", MaxPayloadBytes))
	if _, err := ParsePullRequest(body); !errors.Is(err, ErrPayload) {
		t.Fatalf("err = %v, want ErrPayload", err)
	}
	if err := VerifySignature([]byte("k"), body, sign([]byte("k"), body)); !errors.Is(err, ErrSignature) {
		t.Fatalf("oversized body signature: err = %v, want ErrSignature", err)
	}
}

func TestGitRef(t *testing.T) {
	for _, ok := range []string{"main", "feature/login", "release-1.2", "fix_bug", "user/a.b"} {
		if err := GitRef(ok); err != nil {
			t.Errorf("GitRef(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "@", "/main", "main/", "main.", "a..b", "a//b", "a@{1}", ".hidden", "a/.b", "x.lock", "a/b.lock",
		"a b", "a~1", "a^", "a:b", "a?", "a*", "a[", `a\b`, "a\x00", "a\x7f", strings.Repeat("a", 256),
	} {
		if err := GitRef(bad); err == nil {
			t.Errorf("GitRef(%q) accepted", bad)
		}
	}
}

func TestErrorsBoundUntrustedInput(t *testing.T) {
	long := strings.Repeat("x", 10_000)
	for _, err := range []error{RepoFullName(long), GitRef(long), CommitSHA(long), DNSLabel(long), DNSName(long), Login(long)} {
		if err == nil || len(err.Error()) > 200 {
			t.Fatalf("error not bounded: %d bytes", len(err.Error()))
		}
	}
}
