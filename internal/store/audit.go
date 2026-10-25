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
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
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
	auditDetailOptIn       = "opt_in"
)

// auditDetails is the closed vocabulary of detail for kind; ok is false for
// an unknown kind. The schema's CHECK admits their union; the store admits
// only the pair.
func auditDetails(kind AuditKind) (details []string, ok bool) {
	switch kind {
	case AuditTrustedDeploy:
		return []string{auditDetailWriteAccess}, true
	case AuditUntrustedDeploy, AuditApprovalGranted:
		return []string{string(ApprovalViaReview), string(ApprovalViaLabel), string(ApprovalViaMR)}, true
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
		return []string{auditDetailOptIn}, true
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

// querier is a *sql.DB or a *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// AuditHead is where a verified chain ends: its row count and the hash of
// its last row (64 zeros for an empty trail). Recording it outside the host
// anchors the trail: a later chain that no longer holds that hash was
// truncated or rewritten.
type AuditHead struct {
	Rows int64
	Hash string
}

// AuditRecord is one exported row (previewd audit export, JSON Lines).
// prev_hash and hash let a third party recompute the chain: hash =
// SHA-256(prev_hash || "previewd-audit-v1\n" || each column from id to
// detail as <decimal byte length>:<bytes>,).
type AuditRecord struct {
	ID         int64  `json:"id"`
	At         string `json:"at"`    // RFC 3339, UTC, milliseconds
	AtMillis   int64  `json:"at_ms"` // the value the hash covers
	Kind       string `json:"kind"`
	EnvID      string `json:"environment_id"`
	Repo       string `json:"repository"`
	PRNumber   int64  `json:"pr_number"`
	CommitSHA  string `json:"commit_sha"`
	ActorLogin string `json:"actor_login"`
	ActorID    int64  `json:"actor_id"`
	Detail     string `json:"detail"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
}

const queryAuditRows = `
	SELECT id, at, kind, preview_id, repo, pr_number, commit_sha, actor_login, actor_id, detail, prev_hash, hash
	FROM audit_events ORDER BY id`

// walkAudit recomputes the chain from the first row and hands every row
// that verifies to fn, in order: positions are 1..n without a gap, every
// prev_hash is the previous row's hash, every hash is recomputed. The first
// break stops the walk with ErrAuditChain, naming the row; fn never sees a
// row that does not verify.
func walkAudit(ctx context.Context, db querier, fn func(auditRow) error) (head AuditHead, err error) {
	rows, err := db.QueryContext(ctx, queryAuditRows)
	if err != nil {
		return AuditHead{}, fmt.Errorf("verify audit: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("verify audit: close: %w", closeErr))
		}
	}()
	head.Hash = zeroHash
	for rows.Next() {
		var r auditRow
		var kind string
		e := &r.Event
		if err := rows.Scan(&r.ID, &r.At, &kind, &e.EnvID, &e.Repo, &e.PRNumber, &e.CommitSHA, &e.ActorLogin, &e.ActorID,
			&e.Detail, &r.PrevHash, &r.Hash); err != nil {
			return AuditHead{}, fmt.Errorf("verify audit: scan: %w", err)
		}
		e.Kind = AuditKind(kind)
		switch {
		case r.ID != head.Rows+1:
			return AuditHead{}, fmt.Errorf("%w: row %d where %d was expected", ErrAuditChain, r.ID, head.Rows+1)
		case r.PrevHash != head.Hash:
			return AuditHead{}, fmt.Errorf("%w: row %d does not follow row %d", ErrAuditChain, r.ID, r.ID-1)
		case r.Hash != chainHash(r.PrevHash, r):
			return AuditHead{}, fmt.Errorf("%w: row %d does not match its hash", ErrAuditChain, r.ID)
		}
		if fn != nil {
			if err := fn(r); err != nil {
				return AuditHead{}, err
			}
		}
		head.Rows, head.Hash = r.ID, r.Hash
	}
	if err := rows.Err(); err != nil {
		return AuditHead{}, fmt.Errorf("verify audit: %w", err)
	}
	return head, nil
}

// VerifyAudit recomputes the chain from the first row. Any break is
// ErrAuditChain, naming the first broken row.
func (s *Store) VerifyAudit(ctx context.Context) error {
	_, err := walkAudit(ctx, s.db, nil)
	return err
}

// AuditReader reads the audit trail of a database file without writing to
// it (previewd audit verify|export): opened read-only and query-only,
// never migrated, at this binary's schema version only. It can run beside
// the daemon (WAL readers do not block the writer) or on a copy.
type AuditReader struct {
	db *sql.DB
}

// OpenAuditReader opens path read-only. A database at another schema
// version is refused: an older one must first be migrated by the daemon,
// a newer one belongs to a newer binary.
func OpenAuditReader(ctx context.Context, path string) (*AuditReader, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("audit: database path %s is empty or contains '?' or '#'", quoted(path))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("audit: database path: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String())
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", abs, err)
	}
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return nil, errors.Join(fmt.Errorf("audit: read schema version of %s: %w", abs, err), db.Close())
	}
	if version != len(migrations) {
		return nil, errors.Join(fmt.Errorf("audit: %s is at schema version %d, this binary reads %d: start the matching daemon once to migrate it",
			abs, version, len(migrations)), db.Close())
	}
	if err := verifySchema(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return &AuditReader{db: db}, nil
}

// Verify recomputes the whole chain and returns its head.
func (r *AuditReader) Verify(ctx context.Context) (AuditHead, error) {
	return walkAudit(ctx, r.db, nil)
}

// Export writes every row to w as JSON Lines, oldest first, and returns
// the head. In one read snapshot it first verifies the whole chain, then
// writes it: a chain with any break (ErrAuditChain) writes nothing. A row
// rewritten with its own hash recomputed verifies against its predecessor
// and breaks only at the next row, so streaming would have written it.
func (r *AuditReader) Export(ctx context.Context, w io.Writer) (head AuditHead, err error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AuditHead{}, fmt.Errorf("export audit: begin: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("export audit: end snapshot: %w", rbErr))
		}
	}()
	verified, err := walkAudit(ctx, tx, nil)
	if err != nil {
		return AuditHead{}, err
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	head, err = walkAudit(ctx, tx, func(row auditRow) error {
		e := row.Event
		if err := enc.Encode(AuditRecord{
			ID: row.ID, At: time.UnixMilli(row.At).UTC().Format("2006-01-02T15:04:05.000Z07:00"), AtMillis: row.At,
			Kind: string(e.Kind), EnvID: e.EnvID, Repo: e.Repo, PRNumber: e.PRNumber, CommitSHA: e.CommitSHA,
			ActorLogin: e.ActorLogin, ActorID: e.ActorID, Detail: e.Detail, PrevHash: row.PrevHash, Hash: row.Hash,
		}); err != nil {
			return fmt.Errorf("export audit row %d: %w", row.ID, err)
		}
		return nil
	})
	if err != nil {
		return AuditHead{}, err
	}
	if head != verified {
		return AuditHead{}, fmt.Errorf("%w: the chain changed within one snapshot", ErrAuditChain)
	}
	if err := bw.Flush(); err != nil {
		return AuditHead{}, fmt.Errorf("export audit: %w", err)
	}
	return head, nil
}

// Contains reports whether a row of the trail carries hash. Run after
// Verify: the head of an intact chain names every row before it.
func (r *AuditReader) Contains(ctx context.Context, hash string) (bool, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE hash = ?`, hash).Scan(&n); err != nil {
		return false, fmt.Errorf("audit: look up head: %w", err)
	}
	return n > 0, nil
}

// Close closes the database.
func (r *AuditReader) Close() error {
	return r.db.Close()
}
