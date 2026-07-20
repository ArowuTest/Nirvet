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
	// Own-tenant cleanup (test isolation): scoped to this run's unique tenant, so it touches no other test's
	// rows. Prevents this test's job leaking into the shared ingest_jobs table across `-count` iterations.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ingest_jobs WHERE tenant_id=$1`, tid)
	})

	// Enqueue + claim → the job is now 'running' with claimed_at=now().
	if err := q.Enqueue(ctx, tid, "normalize", []byte(`{}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Backdate run_at so this tenant's job deterministically outranks any concurrent foreign now() rows other
	// test packages enqueue to the shared table — otherwise the fair-claim batch of 10 could be filled by
	// foreign rn=1 jobs and this test's single job would miss it (a shared-table flake, not a queue bug).
	if _, err := pool.Exec(ctx, `UPDATE ingest_jobs SET run_at = now() - interval '10 minutes' WHERE tenant_id=$1`, tid); err != nil {
		t.Fatalf("backdate: %v", err)
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
