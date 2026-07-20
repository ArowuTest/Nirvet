package billing

// §6.17 #174 Billing slice C tests (DB-gated). Margin = billed revenue − operator cost, integer minor-units, with
// the CostConfigured honesty flag and nil-bps on zero revenue. Finance export rolls the billable tenants; totals are
// isolated per test via a unique currency so parallel tenants from other tests don't pollute the assertion.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// uniqCurrency returns a per-test currency code so finance/margin currency totals only include this test's tenants.
func uniqCurrency() string { return "Z" + strings.ToUpper(uuid.NewString()[:4]) }

// setCost sets an operator cost rate directly (test helper; the service path is covered by TestSetCostRate_Audited).
func setCost(t *testing.T, svc *Service, metric Metric, costMinor int64) {
	t.Helper()
	if err := svc.repo.setCostRate(context.Background(), metric, costMinor); err != nil {
		t.Fatalf("set cost: %v", err)
	}
}

// TestMargin_RevenueMinusCost: revenue = overage×rate, cost = usage×cost_rate, margin = revenue−cost, bps correct.
func TestMargin_RevenueMinusCost(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()
	a := padminP()
	cur := uniqCurrency()

	tid := billTenant(t, db)
	pkg, err := svc.CreatePackage(ctx, a, "mgn-"+uuid.NewString(), cur)
	if err != nil {
		t.Fatalf("pkg: %v", err)
	}
	// alert_count: 0 included, 100 minor/over → all usage is overage revenue.
	if err := svc.SetRate(ctx, a, pkg, MetricAlertCount, 0, 100); err != nil {
		t.Fatalf("rate: %v", err)
	}
	if err := svc.AssignPackage(ctx, a, tid, pkg); err != nil {
		t.Fatalf("assign: %v", err)
	}
	now := time.Now().UTC()
	period := now.Format("2006-01")
	if _, err := svc.RecordUsage(ctx, tid, MetricAlertCount, 10, "mgn:alerts", "test", now); err != nil {
		t.Fatalf("usage: %v", err)
	}
	setCost(t, svc, MetricAlertCount, 30) // operator cost 30 minor/unit

	m, err := svc.TenantMargin(ctx, tid, period)
	if err != nil {
		t.Fatalf("margin: %v", err)
	}
	// revenue = 10×100 = 1000; cost = 10×30 = 300; margin = 700; bps = 700*10000/1000 = 7000.
	if m.RevenueMinor != 1000 || m.CostMinor != 300 || m.MarginMinor != 700 {
		t.Fatalf("margin math: %+v (want revenue 1000 cost 300 margin 700)", m)
	}
	if m.MarginBps == nil || *m.MarginBps != 7000 {
		t.Fatalf("margin bps: %+v (want 7000)", m.MarginBps)
	}
	if !m.CostConfigured {
		t.Fatal("CostConfigured must be true once a nonzero cost rate exists")
	}
}

// TestMargin_CostNotConfigured: with NO operator cost set, cost=0 and margin==revenue, but CostConfigured=false so the
// 100% margin is not read as real.
func TestMargin_CostNotConfigured(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()
	a := padminP()
	cur := uniqCurrency()

	tid := billTenant(t, db)
	pkg, _ := svc.CreatePackage(ctx, a, "nc-"+uuid.NewString(), cur)
	_ = svc.SetRate(ctx, a, pkg, MetricAlertCount, 0, 100)
	_ = svc.AssignPackage(ctx, a, tid, pkg)
	now := time.Now().UTC()
	_, _ = svc.RecordUsage(ctx, tid, MetricAlertCount, 5, "nc:alerts", "test", now)

	// Force every cost rate to 0 (the seeded default) so no cost is configured for THIS assertion.
	for _, mtr := range []Metric{MetricAlertCount, MetricLogVolume, MetricReportCount, MetricPlaybookActions,
		MetricConnectorCount, MetricAssetCount, MetricAPIUsage, MetricStorage} {
		setCost(t, svc, mtr, 0)
	}
	m, err := svc.TenantMargin(ctx, tid, now.Format("2006-01"))
	if err != nil {
		t.Fatalf("margin: %v", err)
	}
	if m.CostMinor != 0 || m.MarginMinor != m.RevenueMinor {
		t.Fatalf("unconfigured cost: margin must equal revenue, got %+v", m)
	}
	if m.CostConfigured {
		t.Fatal("CostConfigured must be FALSE when no operator cost is set (no fake 100% margin)")
	}
}

// TestMargin_ZeroRevenue_NilBps: a tenant with no package/usage has 0 revenue → MarginBps is nil (no div-by-zero).
func TestMargin_ZeroRevenue_NilBps(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()
	tid := billTenant(t, db)
	m, err := svc.TenantMargin(ctx, tid, time.Now().UTC().Format("2006-01"))
	if err != nil {
		t.Fatalf("margin: %v", err)
	}
	if m.RevenueMinor != 0 || m.MarginBps != nil {
		t.Fatalf("zero-revenue margin must have nil bps, got %+v", m)
	}
}

// TestSetCostRate_Audited: the service path writes a billing_config_audit row.
func TestSetCostRate_Audited(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()
	if err := svc.SetCostRate(ctx, padminP(), MetricStorage, 42); err != nil {
		t.Fatalf("set cost rate: %v", err)
	}
	var n int
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM billing_config_audit WHERE action='set_cost_rate'`).Scan(&n)
	}); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if n == 0 {
		t.Fatal("SetCostRate must write a billing_config_audit row")
	}
}

// TestFinanceExport_RollAndCSV: a direct tenant and a comp tenant on the same unique currency roll into the export;
// gross totals include both, payable-by-tenant only the direct one; the CSV carries the rows.
func TestFinanceExport_RollAndCSV(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	ctx := context.Background()
	a := padminP()
	cur := uniqCurrency()
	now := time.Now().UTC()
	period := now.Format("2006-01")

	pkg, _ := svc.CreatePackage(ctx, a, "fx-"+uuid.NewString(), cur)
	_ = svc.SetRate(ctx, a, pkg, MetricAPIUsage, 0, 1) // 1 minor/unit over

	// Direct tenant: 500 units → 500 revenue, payable by tenant.
	direct := billTenant(t, db)
	_ = svc.AssignPackage(ctx, a, direct, pkg)
	_, _ = svc.RecordUsage(ctx, direct, MetricAPIUsage, 500, "fx:direct", "test", now)

	// Comp tenant: metered but zero-charge (mode comp) — still appears, but adds 0 to totals.
	comp := billTenant(t, db)
	_ = svc.AssignPackage(ctx, a, comp, pkg)
	if err := svc.SetMode(ctx, a, comp, ModeComp, nil); err != nil {
		t.Fatalf("set comp mode: %v", err)
	}
	_, _ = svc.RecordUsage(ctx, comp, MetricAPIUsage, 999, "fx:comp", "test", now)

	exp, err := svc.ComputeFinanceExport(ctx, period)
	if err != nil {
		t.Fatalf("finance export: %v", err)
	}
	// Isolated by unique currency: only our two tenants contribute to cur totals.
	if exp.GrossByCurrency[cur] != 500 {
		t.Fatalf("gross[%s] = %d, want 500 (direct 500 + comp 0)", cur, exp.GrossByCurrency[cur])
	}
	if exp.PayableByTenantCurrency[cur] != 500 {
		t.Fatalf("payable[%s] = %d, want 500 (only the direct tenant is tenant-payable)", cur, exp.PayableByTenantCurrency[cur])
	}
	// Both tenants appear as rows.
	var sawDirect, sawComp bool
	for _, r := range exp.Rows {
		if r.TenantID == direct {
			sawDirect = true
			if r.Mode != ModeDirect || !r.PayableByTenant || r.TotalMinor != 500 {
				t.Fatalf("direct row wrong: %+v", r)
			}
		}
		if r.TenantID == comp {
			sawComp = true
			if r.Mode != ModeComp || r.PayableByTenant || r.TotalMinor != 0 {
				t.Fatalf("comp row wrong: %+v", r)
			}
		}
	}
	if !sawDirect || !sawComp {
		t.Fatalf("both tenants must appear in the export (direct=%v comp=%v)", sawDirect, sawComp)
	}
	// CSV carries the header + the direct tenant id + total, and has no formula-injection lead char.
	csv := string(FinanceCSV(exp))
	if !strings.Contains(csv, "period,tenant_id,mode,currency") || !strings.Contains(csv, direct.String()) {
		t.Fatalf("CSV missing header or direct row:\n%s", csv[:min(len(csv), 400)])
	}
}
