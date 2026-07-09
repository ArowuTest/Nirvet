// Package queue is the durable ingestion job queue (ADR-0003). The MVP backend is
// Postgres using FOR UPDATE SKIP LOCKED (the pattern River uses); production
// promotes to GCP Pub/Sub behind the same interface. Jobs carry tenant_id and are
// processed by a system-level worker that applies tenant context per job.
//
// Guarantees: at-least-once delivery, idempotent consumers (dedupe upstream), and
// a dead-letter state after MaxAttempts — a security event is never silently lost.
package queue

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxAttempts before a job is dead-lettered.
const MaxAttempts = 5

// Job is a unit of ingestion work (e.g. normalize a raw event).
type Job struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Kind     string
	Payload  []byte
	Attempts int
}

// Queue enqueues and claims ingestion jobs.
type Queue interface {
	Enqueue(ctx context.Context, tenantID uuid.UUID, kind string, payload []byte) error
	Claim(ctx context.Context, n int) ([]Job, error)
	Complete(ctx context.Context, id uuid.UUID) error
	Fail(ctx context.Context, id uuid.UUID, reason string) error
	// ReapStale requeues jobs stranded in 'running' longer than visibility (a worker crashed between
	// Claim and Complete/Fail). Returns the number reaped. Backends that self-heal (NATS AckWait) no-op.
	ReapStale(ctx context.Context, visibility time.Duration) (int, error)
}

// PostgresQueue is the Postgres-backed queue. It runs at the system level (the
// worker legitimately spans tenants); the actual tenant work uses tenant context.
type PostgresQueue struct {
	pool *pgxpool.Pool
}

// NewPostgres builds the queue.
func NewPostgres(pool *pgxpool.Pool) *PostgresQueue { return &PostgresQueue{pool: pool} }

// Enqueue adds a job.
func (q *PostgresQueue) Enqueue(ctx context.Context, tenantID uuid.UUID, kind string, payload []byte) error {
	_, err := q.pool.Exec(ctx,
		`INSERT INTO ingest_jobs (id, tenant_id, kind, payload, state, run_at)
		 VALUES ($1,$2,$3,$4,'queued', now())`,
		uuid.New(), tenantID, kind, payload)
	return err
}

// Claim atomically claims up to n runnable jobs and marks them running.
func (q *PostgresQueue) Claim(ctx context.Context, n int) ([]Job, error) {
	rows, err := q.pool.Query(ctx,
		`UPDATE ingest_jobs SET state='running', attempts=attempts+1, claimed_at=now()
		   WHERE id IN (
		     SELECT id FROM ingest_jobs
		      WHERE state='queued' AND run_at <= now()
		      ORDER BY run_at
		      FOR UPDATE SKIP LOCKED
		      LIMIT $1)
		 RETURNING id, tenant_id, kind, payload, attempts`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.TenantID, &j.Kind, &j.Payload, &j.Attempts); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// Complete marks a job done. The state='running' guard (carry-forward Low) makes this a no-op if
// the reaper already reclaimed this job after a stall — a slow worker's late Complete must not flip
// a job another worker now owns (or re-completes a reaped one).
func (q *PostgresQueue) Complete(ctx context.Context, id uuid.UUID) error {
	_, err := q.pool.Exec(ctx, `UPDATE ingest_jobs SET state='done', finished_at=now() WHERE id=$1 AND state='running'`, id)
	return err
}

// Fail requeues with backoff, or dead-letters after MaxAttempts. Guarded on state='running' (carry-
// forward Low) so a stale worker's late Fail can't false-dead-letter a job the reaper already requeued.
func (q *PostgresQueue) Fail(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := q.pool.Exec(ctx,
		`UPDATE ingest_jobs
		    SET state = CASE WHEN attempts >= $2 THEN 'dead' ELSE 'queued' END,
		        run_at = now() + ($3 || ' seconds')::interval,
		        last_error = $4
		  WHERE id = $1 AND state = 'running'`,
		id, MaxAttempts, backoffSeconds, reason)
	return err
}

// ReapStale requeues jobs stranded in 'running' past the visibility timeout — a worker that hard-crashed
// (OOM/SIGKILL) between Claim and Complete/Fail would otherwise strand the row forever, silently losing a
// security event (R6-C2). Jobs already at MaxAttempts dead-letter (queryable), the rest return to
// 'queued' for another worker. Runs at the system level; safe to run in multiple worker processes.
func (q *PostgresQueue) ReapStale(ctx context.Context, visibility time.Duration) (int, error) {
	secs := int(visibility.Seconds())
	if secs < 1 {
		secs = 1
	}
	ct, err := q.pool.Exec(ctx,
		`UPDATE ingest_jobs
		    SET state = CASE WHEN attempts >= $1 THEN 'dead' ELSE 'queued' END,
		        run_at = now(),
		        last_error = 'reaped: stale running job (worker crash suspected)'
		  WHERE state = 'running' AND claimed_at < now() - make_interval(secs => $2)`,
		MaxAttempts, secs)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// StartReaper runs ReapStale on a ticker until ctx is cancelled (panic-guarded per tick). visibility is
// how long a job may sit in 'running' before it is presumed lost.
func StartReaper(ctx context.Context, q Queue, log *slog.Logger, interval, visibility time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(log, "ingest-queue-reaper", func() {
				if n, err := q.ReapStale(ctx, visibility); err != nil {
					log.Warn("queue reap failed", "err", err)
				} else if n > 0 {
					log.Warn("queue reaped stale running jobs", "count", n)
				}
			})
		}
	}
}

// backoffSeconds is a simple fixed retry delay (scaffold). Production: exponential.
const backoffSeconds = 30
