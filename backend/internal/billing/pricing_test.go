package billing

// §6.17 #126 B-3/B-4 integration — pricing config (padmin, audited) + overage arithmetic (integer minor-units).

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func padminP() auth.Principal {
	return auth.Principal{UserID: uuid.New(), Role: auth.RolePlatformAdmin, Email: "padmin@bill"}
}

func lineOf(inv *Invoice, m Metric) InvoiceLine {
	for _, l := range inv.Lines {
		if l.Metric == m {
			return l
		}
	}
	return InvoiceLine{}
}

// Overage arithmetic vectors in one invoice: over-threshold, exact-at-threshold, zero-included — all integer minor-units.
func TestInvoice_OverageArithmetic(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	a := padminP()
	ctx := context.Background()

	pkg, err := svc.CreatePackage(ctx, a, "std-"+uuid.NewString(), "NGN")
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	must := func(e error) {
		if e != nil {
			t.Fatalf("setrate: %v", e)
		}
	}
	must(svc.SetRate(ctx, a, pkg, MetricReportCount, 5, 100)) // included 5, ₦1.00/over
	must(svc.SetRate(ctx, a, pkg, MetricAlertCount, 10, 50))  // included 10
	must(svc.SetRate(ctx, a, pkg, MetricAPIUsage, 0, 1))      // zero included
	if err := svc.AssignPackage(ctx, a, tid, pkg); err != nil {
		t.Fatalf("assign: %v", err)
	}

	now := time.Now()
	rec := func(m Metric, q int64) {
		if _, err := svc.RecordUsage(ctx, tid, m, q, string(m)+":batch", "test", now); err != nil {
			t.Fatalf("record %s: %v", m, err)
		}
	}
	rec(MetricReportCount, 8) // over by 3 → 300
	rec(MetricAlertCount, 10) // exact at threshold → 0
	rec(MetricAPIUsage, 1000) // zero included → 1000

	inv, err := svc.ComputeInvoice(ctx, tid, CurrentPeriod())
	if err != nil {
		t.Fatalf("invoice: %v", err)
	}
	if inv.Currency != "NGN" {
		t.Fatalf("invoice currency should be the tenant contract currency, got %s", inv.Currency)
	}
	if l := lineOf(inv, MetricReportCount); l.OverageUnits != 3 || l.LineMinor != 300 {
		t.Fatalf("report_count: over %d line %d, want 3/300", l.OverageUnits, l.LineMinor)
	}
	if l := lineOf(inv, MetricAlertCount); l.OverageUnits != 0 || l.LineMinor != 0 {
		t.Fatalf("alert_count exact-at-threshold must be 0, got over %d line %d", l.OverageUnits, l.LineMinor)
	}
	if l := lineOf(inv, MetricAPIUsage); l.OverageUnits != 1000 || l.LineMinor != 1000 {
		t.Fatalf("api_usage zero-included: over %d line %d, want 1000/1000", l.OverageUnits, l.LineMinor)
	}
	if inv.TotalMinor != 1300 {
		t.Fatalf("invoice total must be 300+0+1000=1300 minor units, got %d", inv.TotalMinor)
	}
}

func TestInvoice_NoPackageEmpty(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	inv, err := svc.ComputeInvoice(context.Background(), tid, CurrentPeriod())
	if err != nil {
		t.Fatalf("invoice: %v", err)
	}
	if len(inv.Lines) != 0 || inv.TotalMinor != 0 {
		t.Fatalf("a tenant with no package must have an empty invoice, got %+v", inv)
	}
}

// M-4: a package/tenant currency mismatch is refused (never sums mixed currencies).
func TestInvoice_CurrencyMismatchRefused(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	a := padminP()
	ctx := context.Background()
	pkg, _ := svc.CreatePackage(ctx, a, "usd-"+uuid.NewString(), "USD")
	if err := svc.AssignPackage(ctx, a, tid, pkg); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// Corrupt the tenant's contract currency to something other than the package's.
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenant_billing SET currency='NGN' WHERE tenant_id=$1`, tid)
		return e
	}); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := svc.ComputeInvoice(ctx, tid, CurrentPeriod()); err == nil {
		t.Fatal("a currency mismatch must be refused (M-4)")
	}
}

func TestPricing_ConfigAudited(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	tid := billTenant(t, db)
	a := padminP()
	ctx := context.Background()
	pkg, _ := svc.CreatePackage(ctx, a, "aud-"+uuid.NewString(), "NGN")
	_ = svc.SetRate(ctx, a, pkg, MetricStorage, 1, 1)
	_ = svc.AssignPackage(ctx, a, tid, pkg)
	var n int
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM billing_config_audit WHERE actor_id=$1`, a.UserID).Scan(&n)
	}); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if n < 3 {
		t.Fatalf("every pricing/plan change must be audited (create+rate+assign ≥3), got %d", n)
	}
}
