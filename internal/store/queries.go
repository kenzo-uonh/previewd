package store

import (
	"context"
	"fmt"
	"time"
)

// EnvironmentRecord models the persistence schema for ephemeral stacks.
type EnvironmentRecord struct {
	ID        string
	PRNumber  int64
	Status    string
	CreatedAt time.Time
}

// UpsertEnvironment records or updates the lifecycle state of a PR environment.
func (s *Store) UpsertEnvironment(ctx context.Context, env EnvironmentRecord) error {
	query := `
		INSERT INTO environments (id, pr_number, status, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status = excluded.status;
	`
	_, err := s.db.ExecContext(ctx, query, env.ID, env.PRNumber, env.Status, env.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to upsert environment record: %w", err)
	}
	return nil
}

// DeleteEnvironment purges the record following exhaustive teardown.
func (s *Store) DeleteEnvironment(ctx context.Context, id string) error {
	query := `DELETE FROM environments WHERE id = ?;`
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete environment record: %w", err)
	}
	return nil
}
