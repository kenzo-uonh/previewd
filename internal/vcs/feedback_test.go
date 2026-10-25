package vcs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func readyStatus() Status {
	return Status{
		Repo: "acme/app", PRNumber: 7, CommitSHA: testHead,
		URL:        "https://pr-7-0a0a0a0a0a.preview.corp",
		Approver:   "lead-dev",
		ApproverID: 7,
		Expires:    time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
	}
}

func TestCommentRendersTheLoopFields(t *testing.T) {
	body, err := readyStatus().Comment()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body, CommentMarker+"\n") {
		t.Errorf("the marker is not the first line:\n%s", body)
	}
	for _, want := range []string{
		"🟢", "https://pr-7-0a0a0a0a0a.preview.corp", "`" + testHead[:12] + "`", "approved by `lead-dev#7`", "2026-10-27 12:00 UTC",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "🔴") {
		t.Errorf("a ready preview is red:\n%s", body)
	}
	if strings.Count(body, CommentMarker) != 1 {
		t.Errorf("the marker appears %d times", strings.Count(body, CommentMarker))
	}
}

func TestCommentOfAFailedDeployNamesTheStepAndHasNoLink(t *testing.T) {
	s := readyStatus()
	s.Failure = "build"
	body, err := s.Comment()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "🔴") || !strings.Contains(body, "`build`") || strings.Contains(body, "🟢") || strings.Contains(body, "https://") {
		t.Errorf("failed comment:\n%s", body)
	}
}

func TestCommentOfATrustedDeployHasNoApprover(t *testing.T) {
	s := readyStatus()
	s.Approver, s.ApproverID = "", 0
	body, err := s.Comment()
	if err != nil || !strings.Contains(body, "trusted") || strings.Contains(body, "approved by") {
		t.Errorf("trusted deploy: %v\n%s", err, body)
	}
}

func TestCommentWithoutExpiry(t *testing.T) {
	s := readyStatus()
	s.Expires = time.Time{}
	body, err := s.Comment()
	if err != nil || !strings.Contains(body, "never") {
		t.Errorf("a preview that does not expire: %v\n%s", err, body)
	}
}

// Fails closed: nothing that could break out of the comment, or point the
// reader elsewhere than a preview URL, is rendered.
func TestCommentRefusesWhatCouldInjectMarkup(t *testing.T) {
	for name, edit := range map[string]func(*Status){
		"credentialed url": func(s *Status) { s.URL = "https://u:p@pr-7.preview.corp" },
		"javascript url":   func(s *Status) { s.URL = "javascript:alert(1)" },
		"file url":         func(s *Status) { s.URL = "file:///etc/passwd" },
		"url with query":   func(s *Status) { s.URL = "https://pr-7.preview.corp/?x=1" },
		"url with markup":  func(s *Status) { s.URL = "https://pr-7.preview.corp/)<script>" },
		"no url":           func(s *Status) { s.URL = "" },
		"short commit":     func(s *Status) { s.CommitSHA = "0123456" },
		"upper commit":     func(s *Status) { s.CommitSHA = strings.ToUpper(testHead) },
		"approver html":    func(s *Status) { s.Approver = "<img src=x onerror=y>" },
		"approver break":   func(s *Status) { s.Approver = "ok\n<!-- previewd-status -->" },
		"approver tick":    func(s *Status) { s.Approver = "x` [click](http://evil)" },
		"long approver":    func(s *Status) { s.Approver = strings.Repeat("a", 300) },
		"approver no id":   func(s *Status) { s.ApproverID = 0 },
		"id without name":  func(s *Status) { s.Approver = "" },
		"step markup":      func(s *Status) { s.Failure = "build`\n# pwned" },
		"zero pr":          func(s *Status) { s.PRNumber = 0 },
	} {
		s := readyStatus()
		edit(&s)
		if body, err := s.Comment(); err == nil {
			t.Errorf("%s: rendered\n%s", name, body)
		}
	}
}

func TestCommitStatusFields(t *testing.T) {
	s := readyStatus()
	for _, tc := range []struct {
		state, wantDesc string
	}{
		{StatePending, "Deploying the preview"},
		{StateSuccess, "Preview ready"},
	} {
		if got := s.description(tc.state); got != tc.wantDesc {
			t.Errorf("description(%s) = %q, want %q", tc.state, got, tc.wantDesc)
		}
	}
	s.Failure = "fetch"
	if got := s.description(StateFailure); got != "Preview failed at fetch" {
		t.Errorf("failure description %q", got)
	}
	for _, d := range []string{s.description(StatePending), s.description(StateFailure)} {
		if len(d) > maxDescription {
			t.Errorf("description %q exceeds %d", d, maxDescription)
		}
	}
}

func TestCheckStatusArguments(t *testing.T) {
	ok := func(state, url string) error { return checkStatus(testHead, state, url, "d") }
	for _, state := range []string{StatePending, StateSuccess, StateFailure} {
		if err := ok(state, ""); err != nil {
			t.Errorf("state %s refused: %v", state, err)
		}
	}
	if err := ok(StateSuccess, "https://pr-7.preview.corp"); err != nil {
		t.Errorf("a preview URL refused: %v", err)
	}
	for name, err := range map[string]error{
		"unknown state": ok("error", ""),
		"empty state":   ok("", ""),
		"bad url":       ok(StateSuccess, "ftp://x"),
		"short sha":     checkStatus("abc", StateSuccess, "", "d"),
		"empty desc":    checkStatus(testHead, StateSuccess, "", ""),
		"control desc":  checkStatus(testHead, StateSuccess, "", "a\nb"),
		"long desc":     checkStatus(testHead, StateSuccess, "", strings.Repeat("a", maxDescription+1)),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A notifier whose project cannot be resolved posts nothing.
func TestNotifierFailsClosedOnAnUnresolvedProject(t *testing.T) {
	p := &recordingProvider{}
	n := NewNotifier(p, func(context.Context, string) (string, error) { return "", errors.New("no such project") })
	if err := n.Begin(context.Background(), readyStatus()); err == nil {
		t.Error("Begin on an unresolved project succeeded")
	}
	if len(p.calls) != 0 {
		t.Errorf("calls on an unresolved project: %v", p.calls)
	}
}

// A failure without a step would render green: refused, nothing posted.
func TestNotifierFailNeedsTheFailedStep(t *testing.T) {
	p := &recordingProvider{}
	if err := NewNotifier(p, nil).Fail(context.Background(), readyStatus()); err == nil || len(p.calls) != 0 {
		t.Errorf("Fail without a step: %v, calls %v", err, p.calls)
	}
}

func TestNotifierSequence(t *testing.T) {
	p := &recordingProvider{}
	n := NewNotifier(p, nil)
	ctx := context.Background()
	s := readyStatus()
	if err := n.Begin(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := n.Succeed(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Failure = "start"
	if err := n.Fail(ctx, s); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"status acme/app " + testHead + " pending  Deploying the preview",
		"status acme/app " + testHead + " success https://pr-7-0a0a0a0a0a.preview.corp Preview ready",
		"comment acme/app 7 🟢",
		"status acme/app " + testHead + " failure  Preview failed at start",
		"comment acme/app 7 🔴",
	}
	if strings.Join(p.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls\n%s\nwant\n%s", strings.Join(p.calls, "\n"), strings.Join(want, "\n"))
	}
}

// Both writes are attempted and both failures are reported: a status that
// cannot be set does not hide a comment that can be posted.
func TestNotifierAttemptsBothAndJoinsTheErrors(t *testing.T) {
	p := &recordingProvider{statusErr: errors.New("403 statuses"), commentErr: errors.New("403 comments")}
	err := NewNotifier(p, nil).Succeed(context.Background(), readyStatus())
	if err == nil || !strings.Contains(err.Error(), "403 statuses") || !strings.Contains(err.Error(), "403 comments") {
		t.Errorf("err = %v; want both failures", err)
	}
	if len(p.calls) != 2 {
		t.Errorf("calls %v; want both attempted", p.calls)
	}
}

type recordingProvider struct {
	Provider
	calls                 []string
	statusErr, commentErr error
}

func (r *recordingProvider) SetCommitStatus(_ context.Context, project, sha, state, url, desc string) error {
	r.calls = append(r.calls, "status "+project+" "+sha+" "+state+" "+url+" "+desc)
	return r.statusErr
}

func (r *recordingProvider) PostComment(_ context.Context, project, iid, body string) error {
	icon := "🟢"
	if strings.Contains(body, "🔴") {
		icon = "🔴"
	}
	r.calls = append(r.calls, "comment "+project+" "+iid+" "+icon)
	return r.commentErr
}
