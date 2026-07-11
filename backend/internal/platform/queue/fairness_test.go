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

	const flood = 15
	for i := 0; i < flood; i++ {
		if err := q.Enqueue(ctx, noisy, "normalize", []byte(`{}`)); err != nil {
			t.Fatalf("enqueue noisy %d: %v", i, err)
		}
	}
	if err := q.Enqueue(ctx, quiet, "normalize", []byte(`{}`)); err != nil {
		t.Fatalf("enqueue quiet: %v", err)
	}

	// Claim a batch SMALLER than the flood. Under global FIFO (ORDER BY run_at) the quiet tenant's job — the
	// newest — would sit behind all 15 noisy jobs and never appear. Fair scheduling ranks it rn=1 alongside
	// the noisy tenant's oldest, so it must land in this first batch.
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
