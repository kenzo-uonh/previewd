package validate

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const validReview = `{
  "action": "submitted",
  "review": {
    "id": 77,
    "user": {"login": "lead-dev", "id": 7},
    "commit_id": "0123456789abcdef0123456789abcdef01234567",
    "state": "approved",
    "submitted_at": "2026-10-08T12:01:00Z"
  },
  "pull_request": {
    "number": 42,
    "head": {"ref": "feature/login", "sha": "0123456789abcdef0123456789abcdef01234567", "repo": {"full_name": "fork/shop"}},
    "user": {"login": "octo-cat", "id": 4242},
    "updated_at": "2026-10-08T12:01:00Z"
  },
  "repository": {"full_name": "acme/shop", "clone_url": "https://ghes.example/acme/shop.git"},
  "sender": {"login": "lead-dev", "id": 7}
}`

func TestParseReviewAcceptsValidPayload(t *testing.T) {
	rv, err := ParseReview([]byte(validReview))
	if err != nil {
		t.Fatalf("ParseReview: %v", err)
	}
	at := time.Date(2026, 10, 8, 12, 1, 0, 0, time.UTC)
	want := Review{
		PullRequest: PullRequest{
			Action: ActionSubmitted, Number: 42, Repo: "acme/shop", HeadRef: "feature/login",
			HeadSHA: "0123456789abcdef0123456789abcdef01234567", CloneURL: "https://ghes.example/acme/shop.git",
			HeadRepo: "fork/shop", OpenerLogin: "octo-cat", OpenerID: 4242, UpdatedAt: at,
			SenderLogin: "lead-dev", SenderID: 7,
		},
		State: ReviewApproved, ReviewID: 77, ReviewerLogin: "lead-dev", ReviewerID: 7,
		CommitSHA: "0123456789abcdef0123456789abcdef01234567", SubmittedAt: at,
	}
	if rv != want {
		t.Fatalf("got %+v\nwant %+v", rv, want)
	}
}

// Acted on: an approval, a change request, a dismissal (submitted_at
// optional). Ignored, never acted on: a comment review, an edit, an unknown
// state.
func TestParseReviewActions(t *testing.T) {
	for name, tc := range map[string]struct {
		edits   [][2]string
		ignored bool
	}{
		"changes requested": {edits: [][2]string{{`"approved"`, `"changes_requested"`}}},
		"dismissed":         {edits: [][2]string{{`"submitted"`, `"dismissed"`}, {`"approved"`, `"dismissed"`}}},
		"dismissed, no submitted_at": {edits: [][2]string{{`"submitted"`, `"dismissed"`},
			{`,
    "submitted_at": "2026-10-08T12:01:00Z"`, ``}}},
		"comment review": {edits: [][2]string{{`"approved"`, `"commented"`}}, ignored: true},
		"edited":         {edits: [][2]string{{`"submitted"`, `"edited"`}}, ignored: true},
		"unknown state":  {edits: [][2]string{{`"approved"`, `"approved_by_robot"`}}, ignored: true},
	} {
		body := validReview
		for _, e := range tc.edits {
			if !strings.Contains(body, e[0]) {
				t.Fatalf("%s: edit %q did not apply", name, e[0])
			}
			body = strings.Replace(body, e[0], e[1], 1)
		}
		_, err := ParseReview([]byte(body))
		if tc.ignored != errors.Is(err, ErrIgnoredAction) || (!tc.ignored && err != nil) {
			t.Errorf("%s: %v (ignored %v)", name, err, tc.ignored)
		}
	}
}

// Every required field, removed, rejects the payload.
func TestParseReviewRejectsMissingFields(t *testing.T) {
	paths := [][]string{
		{"action"}, {"review"}, {"review", "id"}, {"review", "user"}, {"review", "user", "login"}, {"review", "user", "id"},
		{"review", "commit_id"}, {"review", "state"}, {"review", "submitted_at"},
		{"pull_request"}, {"pull_request", "number"}, {"pull_request", "head"}, {"pull_request", "head", "ref"},
		{"pull_request", "head", "sha"}, {"pull_request", "user"}, {"pull_request", "updated_at"},
		{"repository"}, {"repository", "full_name"}, {"repository", "clone_url"}, {"sender"}, {"sender", "id"},
	}
	for _, path := range paths {
		var doc map[string]any
		if err := json.Unmarshal([]byte(validReview), &doc); err != nil {
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
		if _, err := ParseReview(body); !errors.Is(err, ErrPayload) {
			t.Errorf("missing %s: err = %v, want ErrPayload", strings.Join(path, "."), err)
		}
	}
}

func TestParseReviewRejectsInvalidFields(t *testing.T) {
	for name, edit := range map[string][2]string{
		"zero review id":     {`"id": 77`, `"id": 0`},
		"negative review id": {`"id": 77`, `"id": -77`},
		"reviewer id zero": {`"login": "lead-dev", "id": 7},
    "commit_id"`, `"login": "lead-dev", "id": 0},
    "commit_id"`},
		"bad reviewer":     {`"user": {"login": "lead-dev"`, `"user": {"login": "lead dev"`},
		"short commit":     {`"commit_id": "0123456789abcdef0123456789abcdef01234567"`, `"commit_id": "0123456"`},
		"upper state":      {`"approved"`, `"APPROVED"`},
		"long state":       {`"approved"`, `"` + strings.Repeat("a", 33) + `"`},
		"bad submitted_at": {`"submitted_at": "2026-10-08T12:01:00Z"`, `"submitted_at": "yesterday"`},
		"zero number":      {`"number": 42`, `"number": 0`},
		"bad clone url":    {`https://ghes.example/acme/shop.git`, `https://u:p@ghes.example/acme/shop.git`},
		"trailing data": {`"sender": {"login": "lead-dev", "id": 7}
}`, `"sender": {"login": "lead-dev", "id": 7}
}}`},
	} {
		body := strings.Replace(validReview, edit[0], edit[1], 1)
		if body == validReview {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := ParseReview([]byte(body)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: err = %v, want ErrPayload", name, err)
		}
	}
}

// Total function + rejection: ParseReview never panics; whatever it returns
// without ErrPayload satisfies every validator independently, and only an
// approval, a change request or a dismissal is acted on.
func FuzzParseReview(f *testing.F) {
	f.Add([]byte(validReview))
	f.Add([]byte(strings.Replace(validReview, `"submitted"`, `"dismissed"`, 1)))
	f.Add([]byte(strings.Replace(validReview, `"approved"`, `"commented"`, 1)))
	f.Add([]byte(strings.Replace(validReview, `"id": 77`, `"id": -1`, 1)))
	f.Add([]byte(strings.Replace(validReview, `{"full_name": "fork/shop"}`, `null`, 1)))
	f.Add([]byte(`{"action":"submitted","review":null}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		rv, err := ParseReview(body)
		switch {
		case err == nil, errors.Is(err, ErrIgnoredAction):
		case errors.Is(err, ErrPayload):
			if rv != (Review{}) {
				t.Fatalf("rejected payload returned data: %+v", rv)
			}
			return
		default:
			t.Fatalf("error is neither ErrPayload nor ErrIgnoredAction: %v", err)
		}
		if len(body) > MaxPayloadBytes || rv.Number == 0 || rv.ReviewID <= 0 || rv.ReviewerID <= 0 ||
			rv.OpenerID <= 0 || rv.SenderID <= 0 || rv.UpdatedAt.Unix() <= 0 {
			t.Fatalf("accepted out-of-range value: %+v", rv)
		}
		for name, check := range map[string]error{
			"repo": RepoFullName(rv.Repo), "ref": GitRef(rv.HeadRef), "head": CommitSHA(rv.HeadSHA),
			"commit": CommitSHA(rv.CommitSHA), "clone": cloneURL(rv.CloneURL), "reviewer": Login(rv.ReviewerLogin),
			"opener": Login(rv.OpenerLogin), "sender": Login(rv.SenderLogin), "state": reviewState(rv.State),
		} {
			if check != nil {
				t.Fatalf("accepted invalid %s: %v", name, check)
			}
		}
		acted := (rv.Action == ActionSubmitted && (rv.State == ReviewApproved || rv.State == ReviewChangesRequested) &&
			!rv.SubmittedAt.IsZero()) || rv.Action == ActionDismissed
		if acted != (err == nil) {
			t.Fatalf("action %q state %q returned err=%v", rv.Action, rv.State, err)
		}
	})
}
