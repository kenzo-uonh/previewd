package store

// Invariant 1 of the store (formal_verification_plan.md section 2):
// high-frequency overlapping read/write transactions never surface
// SQLITE_BUSY. The controls below show the detector is not vacuous: the same
// kind of load on a pool without the connection parameters does.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJobStoreConcurrentTransactionsNeverBusy(t *testing.T) {
	const (
		writers  = 16
		readers  = 4
		opsEach  = 120
		envCount = 6
	)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "previewd.sqlite")
	s := openStore(t, path)
	if _, err := s.StartupSweep(ctx, time.Now(), nil); err != nil {
		t.Fatal(err)
	}

	// A second, independent pool on the same file, like another process
	// (an audit export) reading while the daemon writes.
	name, err := dsn(path)
	if err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := other.Close(); err != nil {
			t.Error(err)
		}
	})

	var (
		seq      atomic.Int64
		mu       sync.Mutex
		errs     []error
		leasedBy = map[int64]int{} // job ID -> number of leases
		wg       sync.WaitGroup
		done     = make(chan struct{})
	)
	record := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}

	for g := range writers {
		wg.Go(func() {
			for i := range opsEach {
				switch (g + i) % 3 {
				case 0:
					d := Delivery{
						ID:    fmt.Sprintf("w%d-%d", g, i),
						EnvID: fmt.Sprintf("pr-%d-0a0a0a0a0a", (g*7+i)%envCount),
						Type:  []JobType{JobDeploy, JobTeardown}[(g+i)%2],
						Seq:   seq.Add(1),
					}
					if _, _, err := s.Enqueue(ctx, d); err != nil {
						record(fmt.Errorf("enqueue: %w", err))
					}
				case 1:
					l, ok, err := s.Acquire(ctx, time.Now())
					if err != nil {
						record(fmt.Errorf("acquire: %w", err))
						continue
					}
					if !ok {
						continue
					}
					mu.Lock()
					leasedBy[l.JobID]++
					mu.Unlock()
					switch {
					case l.Type == JobTeardown && i%4 == 1:
						err = s.Requeue(ctx, l, time.Now())
					case l.Type == JobDeploy && i%5 == 1:
						err = s.Finish(ctx, l, StatusFailed)
					default:
						err = s.Finish(ctx, l, StatusSuccess)
					}
					if err != nil {
						record(fmt.Errorf("complete job %d: %w", l.JobID, err))
					}
				case 2:
					if _, err := s.Jobs(ctx); err != nil {
						record(fmt.Errorf("list: %w", err))
					}
				}
			}
		})
	}
	var readerWG sync.WaitGroup
	for range readers {
		readerWG.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				if err := longRead(ctx, other); err != nil {
					record(err)
				}
			}
		})
	}
	wg.Wait()
	close(done)
	readerWG.Wait()

	for _, err := range errs {
		if isBusy(err) {
			t.Errorf("SQLITE_BUSY surfaced: %v", err)
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	// Drain: every job ends terminal, no lease was handed out twice for a
	// job that was not requeued.
	for {
		l, ok, err := s.Acquire(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		leasedBy[l.JobID]++
		if err := s.Finish(ctx, l, StatusSuccess); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := s.Jobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) == 0 {
		t.Fatal("no job was enqueued: the load did not run")
	}
	for _, j := range jobs {
		if j.Status == StatusQueued || j.Status == StatusInProgress {
			t.Errorf("job %+v left non-terminal", j)
		}
		if n := leasedBy[j.ID]; n > int(j.Attempts)+1 {
			t.Errorf("job %d leased %d times with %d requeues", j.ID, n, j.Attempts)
		}
	}
}

// longRead holds a read transaction across several statements, as an
// export would.
func longRead(ctx context.Context, db *sql.DB) (err error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin read: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("end read: %w", rbErr))
		}
	}()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM jobs`).Scan(&n); err != nil {
		return fmt.Errorf("read jobs: %w", err)
	}
	time.Sleep(200 * time.Microsecond)
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM deliveries`).Scan(&n); err != nil {
		return fmt.Errorf("read deliveries: %w", err)
	}
	return nil
}

// Controls: read-then-write transactions on pools without the store's
// parameters do hit SQLITE_BUSY, so the test above would see it.
// Without busy_timeout the lock wait fails at once; with it but with
// deferred transactions, upgrading a stale read snapshot to a write fails
// regardless of the timeout. Only IMMEDIATE + busy_timeout avoids both.
func TestBusyDetectorControls(t *testing.T) {
	for name, query := range map[string]string{
		"no busy_timeout, deferred": "_pragma=journal_mode(WAL)",
		"busy_timeout, deferred":    "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "control.sqlite")
			db, err := sql.Open("sqlite", path+"?"+query)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			})
			db.SetMaxOpenConns(8)
			if _, err := db.ExecContext(ctx, `CREATE TABLE c (n INTEGER)`); err != nil {
				t.Fatal(err)
			}

			var busy atomic.Bool
			deadline := time.Now().Add(10 * time.Second)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					for !busy.Load() && time.Now().Before(deadline) {
						if err := readThenWrite(ctx, db); isBusy(err) {
							busy.Store(true)
						} else if err != nil {
							t.Errorf("unexpected error: %v", err)
							return
						}
					}
				})
			}
			wg.Wait()
			if !busy.Load() {
				t.Fatal("no SQLITE_BUSY without the store's parameters: the detector proves nothing")
			}
		})
	}
}

func readThenWrite(ctx context.Context, db *sql.DB) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				err = errors.Join(err, rbErr)
			}
		}
	}()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM c`).Scan(&n); err != nil {
		return err
	}
	time.Sleep(100 * time.Microsecond)
	if _, err := tx.ExecContext(ctx, `INSERT INTO c (n) VALUES (?)`, n); err != nil {
		return err
	}
	return tx.Commit()
}
