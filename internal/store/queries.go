package store

import "time"

// EnvironmentRecord models the persistence schema for ephemeral stacks.
type EnvironmentRecord struct {
	ID        string
	PRNumber  int
	Status    string
	CreatedAt time.Time
}
