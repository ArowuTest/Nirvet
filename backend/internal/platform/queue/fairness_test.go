package queue

// M-3: Claim schedules fairly across tenants. A noisy tenant that floods the queue first must not starve a
// quiet tenant's later-arriving security event. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresQueue_ClaimTenantFairness(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	q := NewPostgres(pool)

	noisy := uuid.New() // floods the queue FIRST (earliest run_at)
	quiet := uuid.New() // one job, enqueued LAST (latest run_at)

	// Own-tenant cleanup (test isolation): this test enqueues 16 jobs but claims only 10, leaving 6 noisy jobs
	// 'queued'. Without cleanup those leak into the shared table and, under `go test -count=N`, accumulate as
	// backdated rn=1 rows that starve later iterations. Delete this test's two tenants entirely on exit — they
	// are unique per-run UUIDs, so the delete is strictly scoped and touches no other test's rows.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ingest_jobs WHERE tenant_id = ANY($1)`, []uuid.UUID{noisy, quiet})
	})

	const flood = 15
	for i := 0; i < flood; i++ {
		if err := q.Enqueue(ctx, noisy, "normalize", []byte(`{}`)); err != nil {
			t.Fatalf("enqueue noisy %d: %v", i, err)
		}
	}
	if err := q.Enqueue(ctx, quiet, "normalize", []byte(`{}`)); err != nil {
		t.Fatalf("enqueue quiet: %v", err)
	}

	// Test isolation (CI-race fix): ingest_jobs is a SHARED table and other test packages (integrationtest,
	// schemacheck) enqueue their own jobs with run_at=now() concurrently under `go test ./...`. Those foreign
	// rows are rn=1 for their tenants too, so a plain now() scenario could see them fill the fair-claim batch
	// ahead of THIS test's quiet job (its own run_at is newest) and starve it — a flake, not a bug in Claim.
	// Backdate ONLY this test's two tenants into the past so their rn=1 jobs deterministically outrank any
	// concurrent now() foreign rows. Relative order is preserved — noisy still arrived FIRST (older), quiet
	// still arrived LAST (newer than noisy, but older than any foreign now() row) — so the round-robin-vs-FIFO
	// distinction below is unchanged; only cross-package contention is removed.
	if _, err := pool.Exec(ctx, `UPDATE ingest_jobs SET run_at = now() - interval '10 minutes' WHERE tenant_id = $1`, noisy); err != nil {
		t.Fatalf("backdate noisy: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE ingest_jobs SET run_at = now() - interval '5 minutes' WHERE tenant_id = $1`, quiet); err != nil {
		t.Fatalf("backdate quiet: %v", err)
	}

	// Claim a batch SMALLER than the flood. Under global FIFO (ORDER BY run_at) the quiet tenant's job — the
	// newest of our two — would sit behind all 15 noisy jobs and never appear. Fair scheduling ranks it rn=1
	// alongside the noisy tenant's oldest, so it must land in this first batch.
	jobs, err := q.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	sawQuiet := false
	noisyCount := 0
	for _, j := range jobs {
		switch j.TenantID {
		case quiet:
			sawQuiet = true
		case noisy:
			noisyCount++
		}
	}
	if !sawQuiet {
		t.Fatalf("quiet tenant starved: claimed batch had %d noisy jobs and no quiet job (global-FIFO behavior)", noisyCount)
	}
	// Complete what we claimed so we don't strand running rows for other tests.
	for _, j := range jobs {
		_ = q.Complete(ctx, j.ID)
	}
}
