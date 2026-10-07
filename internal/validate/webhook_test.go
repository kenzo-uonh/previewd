package validate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

const validPayload = `{
  "action": "opened",
  "number": 42,
  "pull_request": {"head": {"ref": "feature/login", "sha": "0123456789abcdef0123456789abcdef01234567"}},
  "repository": {"full_name": "acme/shop", "clone_url": "https://ghes.example/acme/shop.git"}
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
		for name, check := range map[string]error{
			"repo": RepoFullName(pr.Repo), "ref": GitRef(pr.HeadRef), "sha": CommitSHA(pr.HeadSHA), "clone": cloneURL(pr.CloneURL),
		} {
			if check != nil {
				t.Fatalf("accepted invalid %s: %v", name, check)
			}
		}
		acted := pr.Action == ActionOpened || pr.Action == ActionReopened || pr.Action == ActionSynchronize || pr.Action == ActionClosed
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
	}
	if pr != want {
		t.Fatalf("got %+v, want %+v", pr, want)
	}
}

// Every required field, removed, rejects the payload.
func TestParsePullRequestRejectsMissingFields(t *testing.T) {
	paths := [][]string{
		{"action"}, {"number"}, {"pull_request"}, {"pull_request", "head"}, {"pull_request", "head", "ref"},
		{"pull_request", "head", "sha"}, {"repository"}, {"repository", "full_name"}, {"repository", "clone_url"},
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
	for _, err := range []error{RepoFullName(long), GitRef(long), CommitSHA(long), DNSLabel(long), DNSName(long)} {
		if err == nil || len(err.Error()) > 200 {
			t.Fatalf("error not bounded: %d bytes", len(err.Error()))
		}
	}
}
