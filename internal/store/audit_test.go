package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A refused audit event never echoes a caller-supplied string unbounded.
func TestInvalidAuditErrorIsBounded(t *testing.T) {
	s, _ := sweptStore(t)
	ev := testAuditEvent(AuditFullSecretsOptIn, "opt_in")
	ev.ActorLogin, ev.ActorID = strings.Repeat("\x1b[2J", 10_000), 1
	err := s.AppendAudit(context.Background(), ev, t0)
	if !errors.Is(err, ErrInvalidAudit) {
		t.Fatalf("AppendAudit with a 40 KB login: %v, want ErrInvalidAudit", err)
	}
	if len(err.Error()) > 200 || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("error not bounded or not escaped: %d bytes", len(err.Error()))
	}
}
