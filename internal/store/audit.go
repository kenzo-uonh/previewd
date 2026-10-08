package store

// The audit trail: append-only, hash-chained, never pruned (V1 spec 3.1).
// Row n carries hash_n = SHA-256(hash_{n-1} || canonical(row n)) in hex, with
// 64 zeros before the first row. Triggers refuse UPDATE and DELETE; the chain
// detects a row changed, inserted, reordered or deleted behind them (raw
// file edits with the triggers dropped). Truncating the newest rows leaves a
// valid shorter chain: an export of the head hash anchors it (D7).
//
// Every authorization decision writes its row in the transaction of the job
// transition it causes.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// AuditKind is the closed vocabulary of audit_events.kind.
type AuditKind string

// Audit kinds.
const (
	AuditTrustedDeploy    AuditKind = "trusted_deploy"
	AuditUntrustedDeploy  AuditKind = "untrusted_deploy"
	AuditApprovalGranted  AuditKind = "approval_granted"
	AuditApprovalRevoked  AuditKind = "approval_revoked"
	AuditDeployRefused    AuditKind = "deploy_refused"
	AuditTeardown         AuditKind = "teardown"
	AuditTTLExpired       AuditKind = "ttl_expired"
	AuditFullSecretsOptIn AuditKind = "full_secrets_opt_in" // #nosec G101 -- an audit kind name (D-V1-1 opt-in), not a credential
)

// Audit details the store writes itself.
const (
	auditDetailWriteAccess = "write_access"
	auditDetailNotApproved = "not_approved"
)

// auditDetails is the closed vocabulary of detail for kind; ok is false for
// an unknown kind. The schema's CHECK admits their union; the store admits
// only the pair.
func auditDetails(kind AuditKind) (details []string, ok bool) {
	switch kind {
	case AuditTrustedDeploy:
		return []string{auditDetailWriteAccess}, true
	case AuditUntrustedDeploy, AuditApprovalGranted:
		return []string{string(ApprovalViaReview), string(ApprovalViaLabel)}, true
	case AuditApprovalRevoked:
		return []string{string(RevokedDismissed), string(RevokedChangesRequested), string(RevokedUnlabeled),
			string(RevokedNewHead), string(RevokedApproverRemoved), string(RevokedPermissionLost),
			string(RevokedRevalidationUnavailable), string(RevokedPRClosed)}, true
	case AuditDeployRefused:
		return []string{auditDetailNotApproved, string(FailureDiskFloor)}, true
	case AuditTeardown:
		return []string{string(OriginWebhook), string(OriginRevocation), string(OriginRevalidation),
			string(RevokedRevalidationUnavailable)}, true
	case AuditTTLExpired:
		return []string{string(OriginTTL)}, true
	case AuditFullSecretsOptIn:
		return []string{"opt_in"}, true
	}
	return nil, false
}

// Audit errors.
var (
	ErrInvalidAudit = errors.New("invalid audit event")
	ErrAuditChain   = errors.New("audit chain broken")
)

// zeroHash is the prev_hash of the first row.
const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// auditDomain separates this chain's hashes from any other SHA-256 use.
const auditDomain = "previewd-audit-v1\n"

// AuditEvent is one audit row before it is chained. ActorLogin and ActorID
// name the GitHub account behind the decision (login#id), both empty for
// previewd itself. Detail is from the kind's closed vocabulary.
type AuditEvent struct {
	Kind       AuditKind
	EnvID      string
	Repo       string
	PRNumber   int64
	CommitSHA  string // "" when none applies
	ActorLogin string
	ActorID    int64
	Detail     string
}

func (e AuditEvent) validate() error {
	details, ok := auditDetails(e.Kind)
	switch {
	case !ok:
		return fmt.Errorf("%w: kind %s", ErrInvalidAudit, quoted(string(e.Kind)))
	case !slices.Contains(details, e.Detail):
		return fmt.Errorf("%w: detail %s for kind %s", ErrInvalidAudit, quoted(e.Detail), e.Kind)
	case !validPreviewID(e.EnvID) || len(e.Repo) < 3 || len(e.Repo) > maxRepoLen || e.PRNumber <= 0:
		return fmt.Errorf("%w: environment %s, repository %s, pull request %d", ErrInvalidAudit, quoted(e.EnvID), quoted(e.Repo), e.PRNumber)
	case e.CommitSHA != "" && !validCommit(e.CommitSHA):
		return fmt.Errorf("%w: commit %s", ErrInvalidAudit, quoted(e.CommitSHA))
	case len(e.ActorLogin) > maxLoginLen || e.ActorID < 0 || (e.ActorID == 0) != (e.ActorLogin == ""):
		return fmt.Errorf("%w: actor %s#%d", ErrInvalidAudit, quoted(e.ActorLogin), e.ActorID)
	}
	return nil
}

// matches refuses an event that does not describe the operation recording
// it: another kind, environment, repository, pull request or commit.
func (e AuditEvent) matches(kind AuditKind, envID, repo string, prNumber int64, commit string) error {
	if e.Kind != kind || e.EnvID != envID || e.Repo != repo || e.PRNumber != prNumber || e.CommitSHA != commit {
		return fmt.Errorf("%w: %s event for %s %s#%d at %s, operation is %s for %s %s#%d at %s", ErrInvalidAudit,
			quoted(string(e.Kind)), quoted(e.EnvID), quoted(e.Repo), e.PRNumber, quoted(e.CommitSHA),
			kind, quoted(envID), quoted(repo), prNumber, quoted(commit))
	}
	return nil
}

// maxQuoted bounds a caller-supplied string quoted in an error.
const maxQuoted = 64

// quoted renders a caller-supplied string for an error message: valid UTF-8,
// at most maxQuoted bytes, quoted so control characters stay visible. The
// store bounds what it records but cannot vouch for what it refuses.
func quoted(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= maxQuoted {
		return strconv.Quote(s)
	}
	cut := maxQuoted
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strconv.Quote(s[:cut]) + fmt.Sprintf("...(%d bytes)", len(s))
}

// auditRow is one stored row.
type auditRow struct {
	ID       int64
	At       int64
	Event    AuditEvent
	PrevHash string
	Hash     string
}

// canonical is the unambiguous encoding the hash covers: every column but
// the hashes, each as <decimal length>:<bytes>, in schema order.
func (r auditRow) canonical() []byte {
	e := r.Event
	fields := []string{
		strconv.FormatInt(r.ID, 10), strconv.FormatInt(r.At, 10), string(e.Kind), e.EnvID, e.Repo,
		strconv.FormatInt(e.PRNumber, 10), e.CommitSHA, e.ActorLogin, strconv.FormatInt(e.ActorID, 10), e.Detail,
	}
	b := []byte(auditDomain)
	for _, f := range fields {
		b = strconv.AppendInt(b, int64(len(f)), 10)
		b = append(b, ':')
		b = append(b, f...)
		b = append(b, ',')
	}
	return b
}

func chainHash(prevHash string, r auditRow) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(r.canonical())
	return hex.EncodeToString(h.Sum(nil))
}

// appendAudit chains e at the end of the trail, inside tx.
func appendAudit(ctx context.Context, tx *sql.Tx, e AuditEvent, at time.Time) error {
	if err := e.validate(); err != nil {
		return err
	}
	if !validTime(at) {
		return fmt.Errorf("append audit: %w", ErrInvalidTime)
	}
	r := auditRow{ID: 1, At: at.UnixMilli(), Event: e, PrevHash: zeroHash}
	var lastID int64
	var lastHash string
	switch err := tx.QueryRowContext(ctx, `SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHash); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("append audit: read chain head: %w", err)
	default:
		r.ID, r.PrevHash = lastID+1, lastHash
	}
	r.Hash = chainHash(r.PrevHash, r)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (id, at, kind, preview_id, repo, pr_number, commit_sha, actor_login, actor_id, detail, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.At, string(e.Kind), e.EnvID, e.Repo, e.PRNumber, e.CommitSHA, e.ActorLogin, e.ActorID, e.Detail,
		r.PrevHash, r.Hash); err != nil {
		return fmt.Errorf("append audit %s of %s: %w", e.Kind, e.EnvID, err)
	}
	return nil
}

// AppendAudit records an event that causes no job transition (e.g. the
// D-V1-1 full-secrets opt-in at deploy), stamped at.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent, at time.Time) error {
	return s.inTx(ctx, "append audit", func(tx *sql.Tx) error {
		return appendAudit(ctx, tx, e, at)
	})
}

// VerifyAudit recomputes the chain from the first row: positions are 1..n
// without a gap, every prev_hash is the previous row's hash, every hash is
// recomputed. Any break is ErrAuditChain, naming the first broken row.
func (s *Store) VerifyAudit(ctx context.Context) (err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, at, kind, preview_id, repo, pr_number, commit_sha, actor_login, actor_id, detail, prev_hash, hash
		FROM audit_events ORDER BY id`)
	if err != nil {
		return fmt.Errorf("verify audit: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("verify audit: close: %w", closeErr))
		}
	}()
	prev, want := zeroHash, int64(1)
	for rows.Next() {
		var r auditRow
		var kind string
		e := &r.Event
		if err := rows.Scan(&r.ID, &r.At, &kind, &e.EnvID, &e.Repo, &e.PRNumber, &e.CommitSHA, &e.ActorLogin, &e.ActorID,
			&e.Detail, &r.PrevHash, &r.Hash); err != nil {
			return fmt.Errorf("verify audit: scan: %w", err)
		}
		e.Kind = AuditKind(kind)
		switch {
		case r.ID != want:
			return fmt.Errorf("%w: row %d where %d was expected", ErrAuditChain, r.ID, want)
		case r.PrevHash != prev:
			return fmt.Errorf("%w: row %d does not follow row %d", ErrAuditChain, r.ID, r.ID-1)
		case r.Hash != chainHash(r.PrevHash, r):
			return fmt.Errorf("%w: row %d does not match its hash", ErrAuditChain, r.ID)
		}
		prev, want = r.Hash, want+1
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("verify audit: %w", err)
	}
	return nil
}
