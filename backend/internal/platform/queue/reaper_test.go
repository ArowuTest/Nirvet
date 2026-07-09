package queue

// ReapStale against a migrated Postgres. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresQueue_ReapStale(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	q := NewPostgres(pool)
	tid := uuid.New()

	// Enqueue + claim → the job is now 'running' with claimed_at=now().
	if err := q.Enqueue(ctx, tid, "normalize", []byte(`{}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	jobs, err := q.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	var claimed *Job
	for i := range jobs {
		if jobs[i].TenantID == tid {
			claimed = &jobs[i]
		}
	}
	if claimed == nil {
		t.Fatal("expected to claim our job")
	}

	// A fresh running job is NOT reaped (claimed within the visibility window).
	if n, err := q.ReapStale(ctx, time.Hour); err != nil || n != 0 {
		// n could be >0 if other stale jobs exist; assert OUR job specifically stays running.
		_ = n
		_ = err
	}
	var state string
	pool.QueryRow(ctx, `SELECT state FROM ingest_jobs WHERE id=$1`, claimed.ID).Scan(&state)
	if state != "running" {
		t.Fatalf("fresh job should still be running, got %s", state)
	}

	// Backdate claimed_at beyond the visibility window → the reaper requeues it.
	if _, err := pool.Exec(ctx, `UPDATE ingest_jobs SET claimed_at = now() - interval '1 hour' WHERE id=$1`, claimed.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := q.ReapStale(ctx, time.Minute); err != nil {
		t.Fatalf("reap: %v", err)
	}
	pool.QueryRow(ctx, `SELECT state FROM ingest_jobs WHERE id=$1`, claimed.ID).Scan(&state)
	if state != "queued" {
		t.Fatalf("stale running job should be requeued to 'queued', got %s", state)
	}
}
