package billing

// ING-010 / BILL-002 — the day-close ingest metering producer actually feeds the ledger (previously RecordUsage
// had NO caller, so log_volume was always 0 and overage never fired). Verifies: the day's raw_events count lands
// as log_volume, a different day's events are excluded, and re-metering the same day is idempotent (no double).

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func seedRawAt(t *testing.T, db *database.DB, tid uuid.UUID, at time.Time, n int) {
	t.Helper()
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		for i := 0; i < n; i++ {
			// enqueued_at is set (= received_at) so these look like real, fully-ingested events — NOT unenqueued
			// orphans. The cross-tenant ingest reconcile (FindUnenqueued) would otherwise pick these test rows up
			// out of the shared CI DB and fail scanning their NULL blob_uri.
			if _, e := tx.Exec(ctx, `INSERT INTO raw_events (id, tenant_id, source, dedupe_key, checksum, payload, received_at, enqueued_at)
				VALUES ($1,$2,'test',$3,'chk',$4,$5,$5)`, uuid.New(), tid, uuid.NewString(), []byte("x"), at); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed raw_events: %v", err)
	}
}

func TestMeterDailyIngest_FeedsLedgerIdempotently(t *testing.T) {
	db := billDB(t)
	tid := billTenant(t, db)
	svc := NewService(NewRepository(db))
	repo := NewRepository(db)
	ctx := context.Background()

	day := time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)
	seedRawAt(t, db, tid, day.Add(2*time.Hour), 3)  // 3 events on the metered day
	seedRawAt(t, db, tid, day.Add(-3*time.Hour), 1) // 1 event the previous day → must NOT be counted
	seedRawAt(t, db, tid, day.Add(26*time.Hour), 2) // 2 events the next day → must NOT be counted

	svc.MeterDailyIngest(ctx, nil, day)
	if got := total(t, repo, tid, periodOf(day), MetricLogVolume); got != 3 {
		t.Fatalf("log_volume should equal only the metered day's ingest count (3), got %d", got)
	}
	// Idempotent: re-metering the same day does not double-count (day-keyed idempotency).
	svc.MeterDailyIngest(ctx, nil, day)
	if got := total(t, repo, tid, periodOf(day), MetricLogVolume); got != 3 {
		t.Fatalf("re-metering the same day must be idempotent, got %d", got)
	}
}
