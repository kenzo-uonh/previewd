package orchestrator

import (
	"context"
	"log/slog"
)

// Job encapsulates the required parameters for provisioning an ephemeral stack.
type Job struct {
	EnvID    string
	PRNumber int
	CloneURL string
	Commit   string
}

// WorkerPool maintains bounded deployment concurrency.
type WorkerPool struct {
	jobs   chan Job
	logger *slog.Logger
}

// NewWorkerPool initializes a fixed-capacity deployment queue.
func NewWorkerPool(capacity int, logger *slog.Logger) *WorkerPool {
	return &WorkerPool{
		jobs:   make(chan Job, capacity),
		logger: logger,
	}
}

// Submit queues a deployment job without blocking the HTTP listener.
func (wp *WorkerPool) Submit(j Job) {
	wp.jobs <- j
}

// Start spawns the background worker to sequentially process deployments.
func (wp *WorkerPool) Start(ctx context.Context, processor func(context.Context, Job) error) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				wp.logger.Info("Worker pool shutting down")
				return
			case job := <-wp.jobs:
				if err := processor(ctx, job); err != nil {
					wp.logger.Error("Deployment job failed", "environment_id", job.EnvID, "error", err)
				}
			}
		}
	}()
}
