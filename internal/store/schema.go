package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// schemaAllowlist pins every table, column and declared type. A column that
// could hold free text is listed only once reviewed to carry no secret
// material. A migration that adds or retypes anything fails verifySchema
// until this list, and that review, are updated.
var schemaAllowlist = map[string]map[string]string{
	"jobs": {
		"id":           "INTEGER", // job ID
		"preview_id":   "TEXT",    // environment ID: envid.Generate output, a DNS label
		"type":         "TEXT",    // deploy or teardown (CHECK)
		"origin":       "TEXT",    // webhook, approval, revocation, revalidation, ttl (CHECK)
		"seq":          "INTEGER", // delivery order
		"status":       "TEXT",    // PENDING_APPROVAL, QUEUED, IN_PROGRESS, SUCCESS, FAILED, SKIPPED (CHECK)
		"trust":        "TEXT",    // unclassified, trusted, untrusted (CHECK)
		"attempts":     "INTEGER", // teardown requeues, deploy requeues while GHES is unavailable
		"not_before":   "INTEGER", // backoff, Unix milliseconds
		"lease_epoch":  "INTEGER", // boot epoch of the lease
		"created_at":   "INTEGER", // Unix milliseconds
		"finished_at":  "INTEGER", // Unix milliseconds, 0 while not terminal
		"failure":      "TEXT",    // closed vocabulary (CHECK), never free text
		"repo":         "TEXT",    // repository full name, validate.RepoFullName
		"head_repo":    "TEXT",    // head repository full name; '' if the fork was deleted or before schema 3
		"pr_number":    "INTEGER", // pull request number
		"opener_login": "TEXT",    // PR opener's GitHub login; '' before schema 3
		"opener_id":    "INTEGER", // PR opener's numeric GitHub ID; 0 before schema 3
		"commit_sha":   "TEXT",    // head commit, validate.CommitSHA (40 or 64 hex)
		"clone_url":    "TEXT",    // validate.cloneURL: absolute, no user info (credentials refused)
	},
	"deliveries": {
		"delivery_id":    "TEXT",    // X-GitHub-Delivery UUIDv1, canonical lower case
		"payload_sha256": "TEXT",    // SHA-256 of the signed body (hex): content replay key
		"preview_id":     "TEXT",    // environment ID: envid.Generate output, a DNS label
		"seq":            "INTEGER", // delivery order
		"verdict":        "TEXT",    // accepted or stale (CHECK)
		"received_at":    "INTEGER", // Unix milliseconds
	},
	"boots": {
		"epoch":      "INTEGER", // boot epoch
		"started_at": "INTEGER", // Unix milliseconds
	},
	"watermarks": {
		"preview_id": "TEXT",    // environment ID
		"seq":        "INTEGER", // highest seq ever recorded, raised before jobs are pruned
	},
	"approvals": {
		"id":             "INTEGER", // grant ID
		"preview_id":     "TEXT",    // environment ID
		"repo":           "TEXT",    // repository full name
		"pr_number":      "INTEGER", // pull request number
		"commit_sha":     "TEXT",    // approved commit (40 or 64 hex)
		"approver_login": "TEXT",    // approver's GitHub login, audit only (matched on approver_id)
		"approver_id":    "INTEGER", // approver's numeric GitHub ID
		"via":            "TEXT",    // review or label (CHECK)
		"review_id":      "INTEGER", // GitHub review ID; 0 for a label approval
		"granted_seq":    "INTEGER", // delivery order of the newest grant
		"granted_at":     "INTEGER", // Unix milliseconds, audit only
	},
	"revocations": {
		"preview_id":  "TEXT",    // environment ID
		"commit_sha":  "TEXT",    // revoked commit (40 or 64 hex), with or without a grant
		"revoked_seq": "INTEGER", // delivery order of the newest revocation
		"revoked_at":  "INTEGER", // Unix milliseconds, audit only
		"reason":      "TEXT",    // closed vocabulary (CHECK)
	},
	"heads": {
		"preview_id": "TEXT",    // environment ID
		"commit_sha": "TEXT",    // head of the newest accepted deploy delivery (40 or 64 hex)
		"seq":        "INTEGER", // its seq: every other commit is revoked at it (new_head)
		"prior_seq":  "INTEGER", // newest accepted deploy seq of another commit: commit_sha is revoked at it
	},
	"audit_events": {
		"id":          "INTEGER", // chain position, from 1
		"at":          "INTEGER", // Unix milliseconds
		"kind":        "TEXT",    // closed vocabulary (CHECK)
		"preview_id":  "TEXT",    // environment ID
		"repo":        "TEXT",    // repository full name
		"pr_number":   "INTEGER", // pull request number
		"commit_sha":  "TEXT",    // commit (40 or 64 hex), '' when none applies
		"actor_login": "TEXT",    // GitHub login of the actor; '' for previewd itself
		"actor_id":    "INTEGER", // numeric GitHub ID of the actor; 0 for previewd itself
		"detail":      "TEXT",    // closed vocabulary per kind (CHECK, auditDetails)
		"prev_hash":   "TEXT",    // hex SHA-256 of the previous row; 64 zeros for the first
		"hash":        "TEXT",    // hex SHA-256 of prev_hash and the canonical row
	},
}

// verifySchema refuses a database whose schema differs from the allowlist in
// either direction (extra or missing table or column, other declared type),
// or that has any column with BLOB affinity (declared BLOB, or no declared
// type), which stores arbitrary bytes. It runs at every start.
func verifySchema(ctx context.Context, db *sql.DB) error {
	tables, err := userTables(ctx, db)
	if err != nil {
		return err
	}

	var violations []string
	present := map[string]bool{}
	for _, table := range tables {
		present[table] = true
		allowed, ok := schemaAllowlist[table]
		if !ok {
			violations = append(violations, fmt.Sprintf("table %q is not allowlisted", table))
			continue
		}
		cols, err := tableColumns(ctx, db, table)
		if err != nil {
			return err
		}
		// The schema is pinned both ways: a missing column means a database
		// from another version that queries would fail on at run time.
		for name := range allowed {
			if _, ok := cols[name]; !ok {
				violations = append(violations, fmt.Sprintf("column %s.%s is missing", table, name))
			}
		}
		for name, declType := range cols {
			if blobAffinity(declType) {
				violations = append(violations, fmt.Sprintf("%s.%s has BLOB affinity (%q)", table, name, declType))
				continue
			}
			want, ok := allowed[name]
			if !ok {
				violations = append(violations, fmt.Sprintf("column %s.%s (%s) is not allowlisted", table, name, declType))
				continue
			}
			if !strings.EqualFold(declType, want) {
				violations = append(violations, fmt.Sprintf("column %s.%s is %q, allowlisted as %q", table, name, declType, want))
			}
		}
	}
	for table := range schemaAllowlist {
		if !present[table] {
			violations = append(violations, fmt.Sprintf("table %q is missing", table))
		}
	}
	if len(violations) > 0 {
		slices.Sort(violations)
		return fmt.Errorf("schema refused: %s", strings.Join(violations, "; "))
	}
	return nil
}

func userTables(ctx context.Context, db *sql.DB) (tables []string, err error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close table list: %w", closeErr))
		}
	}()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	return tables, nil
}

func tableColumns(ctx context.Context, db *sql.DB, table string) (cols map[string]string, err error) {
	// pragma_table_info takes the table name as a bound argument.
	rows, err := db.QueryContext(ctx, `SELECT name, type FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("table info %s: %w", table, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close table info %s: %w", table, closeErr))
		}
	}()
	cols = map[string]string{}
	for rows.Next() {
		var name, declType string
		if err := rows.Scan(&name, &declType); err != nil {
			return nil, fmt.Errorf("scan table info %s: %w", table, err)
		}
		cols[name] = declType
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("table info %s: %w", table, err)
	}
	return cols, nil
}

// blobAffinity applies SQLite's affinity rules (datatype3 §3.1): a declared
// type with "INT" is INTEGER, with "CHAR", "CLOB" or "TEXT" is TEXT; otherwise
// one with "BLOB", or none at all, is BLOB.
func blobAffinity(declType string) bool {
	t := strings.ToUpper(declType)
	if strings.Contains(t, "INT") || strings.Contains(t, "CHAR") || strings.Contains(t, "CLOB") || strings.Contains(t, "TEXT") {
		return false
	}
	return t == "" || strings.Contains(t, "BLOB")
}
