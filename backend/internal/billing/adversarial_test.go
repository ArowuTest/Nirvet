package billing

// §6.17 #126 B-5 — the money-adversarial round. Several probes are STRUCTURAL and proven elsewhere: usage has no
// tenant-writable endpoint (RecordUsage is internal, no route), replay-no-double + negative-reject (metering_test),
// currency-mismatch (pricing_test), and "no float in a money path" is a compile-time property (every money field is
// int64 minor-units). Here: invoice tenant isolation + the code-owned metric registry.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// An invoice composes the tenant's OWN rollup — tenant B's invoice never includes tenant A's usage.
func TestAdversarial_InvoiceTenantIsolation(t *testing.T) {
	db := billDB(t)
	svc := NewService(NewRepository(db))
	a := billTenant(t, db)
	b := billTenant(t, db)
	admin := padminP()
	ctx := context.Background()

	pkg, _ := svc.CreatePackage(ctx, admin, "iso-"+uuid.NewString(), "NGN")
	_ = svc.SetRate(ctx, admin, pkg, MetricAPIUsage, 0, 1)
	// Both tenants on the same package.
	_ = svc.AssignPackage(ctx, admin, a, pkg)
	_ = svc.AssignPackage(ctx, admin, b, pkg)
	// Only tenant A accrues usage.
	if _, err := svc.RecordUsage(ctx, a, MetricAPIUsage, 500, "api:a", "test", time.Now()); err != nil {
		t.Fatalf("record a: %v", err)
	}
	invB, err := svc.ComputeInvoice(ctx, b, CurrentPeriod())
	if err != nil {
		t.Fatalf("invoice b: %v", err)
	}
	if invB.TotalMinor != 0 {
		t.Fatalf("tenant B's invoice must not include tenant A's usage, got total %d", invB.TotalMinor)
	}
	invA, _ := svc.ComputeInvoice(ctx, a, CurrentPeriod())
	if invA.TotalMinor != 500 {
		t.Fatalf("tenant A's own invoice should reflect its usage (500), got %d", invA.TotalMinor)
	}
}

// The metric set is a code-owned allow-list — an unregistered metric can never be metered or rated.
func TestAdversarial_MetricRegistryCodeOwned(t *testing.T) {
	if IsMetric(Metric("free_money")) {
		t.Fatal("an unregistered metric must not be accepted")
	}
	for _, m := range []Metric{MetricLogVolume, MetricReportCount, MetricPlaybookActions, MetricAPIUsage} {
		if !IsMetric(m) {
			t.Fatalf("registered metric %q must be accepted", m)
		}
	}
}
