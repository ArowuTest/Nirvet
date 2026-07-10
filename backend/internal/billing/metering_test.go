package billing

// §6.17 #126 B-1/B-2 integration — the money-integrity core: idempotent point-deltas (no double-count / no loss),
// negative rejected, record-don't-drop for a closed period, reconciliation (rollup == SUM(ledger)), tenant isolation.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func billDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func billTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "bill-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func total(t *testing.T, r *Repository, tid uuid.UUID, period string, m Metric) int64 {
	t.Helper()
	roll, err := r.Rollup(context.Background(), tid, period)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	for _, mt := range roll {
		if mt.Metric == m {
			return mt.Total
		}
	}
	return 0
}

// Idempotency: a replay of the SAME increment key does not double-count; distinct keys sum.
func TestRecordUsage_IdempotentAndSums(t *testing.T) {
	db := billDB(t)
	r := NewRepository(db)
	tid := billTenant(t, db)
	ctx := context.Background()
	now := time.Now()
	period := periodOf(now)

	ins, err := r.RecordUsage(ctx, tid, MetricReportCount, 1, "report_count:r1", "reporting", now)
	if err != nil || !ins {
		t.Fatalf("first record should insert: ins=%v err=%v", ins, err)
	}
	// Replay of the same key → no-op (no double-count).
	ins, err = r.RecordUsage(ctx, tid, MetricReportCount, 1, "report_count:r1", "reporting", now)
	if err != nil || ins {
		t.Fatalf("replay of the same key must be a no-op: ins=%v err=%v", ins, err)
	}
	// A distinct increment → summed.
	if _, err := r.RecordUsage(ctx, tid, MetricReportCount, 1, "report_count:r2", "reporting", now); err != nil {
		t.Fatalf("distinct key: %v", err)
	}
	if got := total(t, r, tid, period, MetricReportCount); got != 2 {
		t.Fatalf("two distinct increments (replay ignored) must total 2, got %d", got)
	}
}

func TestRecordUsage_NegativeAndUnknownRejected(t *testing.T) {
	db := billDB(t)
	r := NewRepository(db)
	tid := billTenant(t, db)
	ctx := context.Background()
	if _, err := r.RecordUsage(ctx, tid, MetricLogVolume, -1, "k", "s", time.Now()); err == nil {
		t.Fatal("negative quantity must be rejected (M-3)")
	}
	if _, err := r.RecordUsage(ctx, tid, Metric("bogus"), 1, "k", "s", time.Now()); err == nil {
		t.Fatal("an unregistered metric must be rejected")
	}
}

// PIN-1: a late event for a CLOSED period is recorded (not dropped) and adjusted forward to the current period, and
// the closed period's rollup is not mutated.
func TestRecordUsage_ClosedPeriodAdjustsForward(t *testing.T) {
	db := billDB(t)
	r := NewRepository(db)
	tid := billTenant(t, db)
	ctx := context.Background()
	closedPeriod := "2020-01"
	if err := r.ClosePeriod(ctx, tid, closedPeriod); err != nil {
		t.Fatalf("close period: %v", err)
	}
	occurred := time.Date(2020, 1, 15, 0, 0, 0, 0, time.UTC) // inside the closed period
	if _, err := r.RecordUsage(ctx, tid, MetricAlertCount, 7, "alert_count:late1", "detect", occurred); err != nil {
		t.Fatalf("record late: %v", err)
	}
	// The closed period is NOT mutated.
	if got := total(t, r, tid, closedPeriod, MetricAlertCount); got != 0 {
		t.Fatalf("a closed period must not be mutated by a late event, got %d", got)
	}
	// The event is NOT dropped — it lands as an adjustment on the current period.
	if got := total(t, r, tid, CurrentPeriod(), MetricAlertCount); got != 7 {
		t.Fatalf("a late event must be adjusted forward (not dropped), current-period total=%d", got)
	}
	var isAdj bool
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT is_adjustment FROM usage_events WHERE tenant_id=$1 AND idempotency_key='alert_count:late1'`, tid).Scan(&isAdj)
	}); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if !isAdj {
		t.Fatal("a forward-adjusted late event must be marked is_adjustment")
	}
}

// M-5: the rollup equals the raw SUM of the append-only ledger — no separate counter to drift.
func TestRollup_ReconcilesToLedgerSum(t *testing.T) {
	db := billDB(t)
	r := NewRepository(db)
	tid := billTenant(t, db)
	ctx := context.Background()
	now := time.Now()
	for i, q := range []int64{3, 5, 11} {
		if _, err := r.RecordUsage(ctx, tid, MetricPlaybookActions, q, "pb:run:"+uuid.NewString(), "soar", now); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	rollup := total(t, r, tid, periodOf(now), MetricPlaybookActions)
	var ledgerSum int64
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(sum(quantity),0) FROM usage_events WHERE tenant_id=$1 AND metric='playbook_actions'`, tid).Scan(&ledgerSum)
	}); err != nil {
		t.Fatalf("ledger sum: %v", err)
	}
	if rollup != ledgerSum || rollup != 19 {
		t.Fatalf("rollup(%d) must equal ledger SUM(%d) == 19", rollup, ledgerSum)
	}
}

func TestRecordUsage_TenantIsolation(t *testing.T) {
	db := billDB(t)
	r := NewRepository(db)
	a := billTenant(t, db)
	b := billTenant(t, db)
	ctx := context.Background()
	now := time.Now()
	if _, err := r.RecordUsage(ctx, a, MetricAPIUsage, 100, "api:a:1", "api", now); err != nil {
		t.Fatalf("record a: %v", err)
	}
	if got := total(t, r, b, periodOf(now), MetricAPIUsage); got != 0 {
		t.Fatalf("tenant B must not see tenant A's usage, got %d", got)
	}
}

// The append-only ledger rejects mutation.
func TestUsageEvents_AppendOnly(t *testing.T) {
	db := billDB(t)
	r := NewRepository(db)
	tid := billTenant(t, db)
	ctx := context.Background()
	if _, err := r.RecordUsage(ctx, tid, MetricStorage, 42, "storage:x", "s", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE usage_events SET quantity=999 WHERE tenant_id=$1`, tid)
		return e
	})
	if err == nil {
		t.Fatal("usage_events must be append-only (UPDATE must fail)")
	}
}
