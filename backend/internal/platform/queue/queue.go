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

// Complete marks a job done.
func (q *PostgresQueue) Complete(ctx context.Context, id uuid.UUID) error {
	_, err := q.pool.Exec(ctx, `UPDATE ingest_jobs SET state='done', finished_at=now() WHERE id=$1`, id)
	return err
}

// Fail requeues with backoff, or dead-letters after MaxAttempts.
func (q *PostgresQueue) Fail(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := q.pool.Exec(ctx,
		`UPDATE ingest_jobs
		    SET state = CASE WHEN attempts >= $2 THEN 'dead' ELSE 'queued' END,
		        run_at = now() + ($3 || ' seconds')::interval,
		        last_error = $4
		  WHERE id = $1`,
		id, MaxAttempts, backoffSeconds, reason)
	return err
}

// backoffSeconds is a simple fixed retry delay (scaffold). Production: exponential.
const backoffSeconds = 30
