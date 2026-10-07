package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store encapsulates the CGO-free SQLite database operations.
type Store struct {
	db *sql.DB
}

// NewStore establishes the database connection and ensures schema readiness.
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("database unreachable: %w", err)
	}

	if err := initializeSchema(ctx, db); err != nil {
		return nil, err
	}
	if err := verifySchema(ctx, db); err != nil {
		return nil, errors.Join(err, db.Close())
	}

	return &Store{db: db}, nil
}

func initializeSchema(ctx context.Context, db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS environments (
		id TEXT PRIMARY KEY,
		pr_number INTEGER NOT NULL,
		status TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to apply schema: %w", err)
	}
	return nil
}

// Close safely terminates the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
