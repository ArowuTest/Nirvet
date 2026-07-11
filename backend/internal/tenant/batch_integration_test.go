package tenant_test

// Bulk onboarding factory — the security spine against a migrated Postgres:
//   - secure defaults at creation: each batch-created tenant gets the fail-closed catch-all authority policy
//     ('*' = observe) and its profile, atomically (ONB-1 — created-and-seeded or not created);
//   - no cross-tenant bleed: each tenant's governance lands ONLY under its own tenant_id;
//   - idempotency (ONB-2): a duplicate external_ref (in-request or already in the DB) is skipped, so a retried
//     batch converges to exactly one tenant per external_ref;
//   - per-row failure isolation: a bad row is reported failed while the valid rows still create;
//   - batch cap (ONB-3): an over-cap request is rejected wholesale.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func batchSvc(t *testing.T) (*tenant.Service, *database.DB) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return tenant.NewService(tenant.NewRepository(db)), db
}

// authorityRowsFor returns the count of authority_policies visible under a tenant's own RLS context and the
// mode of its catch-all '*' policy.
func authorityRowsFor(t *testing.T, db *database.DB, id uuid.UUID) (int, string) {
	t.Helper()
	var n int
	var mode string
	if err := db.WithTenant(context.Background(), id, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM authority_policies`).Scan(&n); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `SELECT coalesce(max(mode),'') FROM authority_policies WHERE action_type='*'`).Scan(&mode)
	}); err != nil {
		t.Fatalf("read authority for %s: %v", id, err)
	}
	return n, mode
}

func TestCreateBatch_SecureDefaults_NoCrossTenantBleed(t *testing.T) {
	svc, db := batchSvc(t)
	ctx := context.Background()
	refA, refB := "mda-"+uuid.NewString(), "mda-"+uuid.NewString()

	res, err := svc.CreateBatch(ctx, []tenant.BatchRow{
		{Name: "Agency A", ExternalRef: refA},
		{Name: "Agency B", ExternalRef: refB},
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if res.Created != 2 || res.Failed != 0 || res.Skipped != 0 {
		t.Fatalf("both rows must create, got created=%d failed=%d skipped=%d", res.Created, res.Failed, res.Skipped)
	}
	for _, rr := range res.Results {
		if rr.Status != "created" || rr.TenantID == nil {
			t.Fatalf("row %s must be created with an id, got %+v", rr.ExternalRef, rr)
		}
		// Secure default: exactly ONE authority policy visible under this tenant — its own fail-closed
		// catch-all '*' = observe. Exactly one proves NO cross-tenant bleed (the sibling row's seed did not
		// also write a row under this tenant), AND that governance was seeded (ONB-1, atomic with create).
		n, mode := authorityRowsFor(t, db, *rr.TenantID)
		if n != 1 || mode != "observe" {
			t.Fatalf("tenant %s must have exactly its own fail-closed policy ('*'=observe), got count=%d mode=%q", rr.ExternalRef, n, mode)
		}
	}
}

func TestCreateBatch_Idempotent(t *testing.T) {
	svc, db := batchSvc(t)
	ctx := context.Background()
	refA, refB, refC := "mda-"+uuid.NewString(), "mda-"+uuid.NewString(), "mda-"+uuid.NewString()

	// First batch creates A, B. An in-request duplicate of A is skipped, not double-created.
	res1, err := svc.CreateBatch(ctx, []tenant.BatchRow{
		{Name: "A", ExternalRef: refA},
		{Name: "A again", ExternalRef: refA},
		{Name: "B", ExternalRef: refB},
	})
	if err != nil {
		t.Fatalf("batch1: %v", err)
	}
	if res1.Created != 2 || res1.Skipped != 1 {
		t.Fatalf("in-request dup must skip: created=%d skipped=%d", res1.Created, res1.Skipped)
	}

	// Re-submitting the same batch (plus a new C) skips the already-created A,B at the DB layer and creates C.
	res2, err := svc.CreateBatch(ctx, []tenant.BatchRow{
		{Name: "A", ExternalRef: refA},
		{Name: "B", ExternalRef: refB},
		{Name: "C", ExternalRef: refC},
	})
	if err != nil {
		t.Fatalf("batch2: %v", err)
	}
	if res2.Created != 1 || res2.Skipped != 2 {
		t.Fatalf("re-submit must skip A,B and create C: created=%d skipped=%d", res2.Created, res2.Skipped)
	}
	// Exactly one tenant exists for refA across both runs (DB unique index converged the retries).
	var count int
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE external_ref=$1`, refA).Scan(&count)
	}); err != nil {
		t.Fatalf("count refA: %v", err)
	}
	if count != 1 {
		t.Fatalf("exactly one tenant must exist for a repeated external_ref, got %d", count)
	}
}

func TestCreateBatch_PerRowFailureIsolation(t *testing.T) {
	svc, _ := batchSvc(t)
	ctx := context.Background()
	res, err := svc.CreateBatch(ctx, []tenant.BatchRow{
		{Name: "Good1", ExternalRef: "mda-" + uuid.NewString()},
		{Name: "BadTier", ServiceTier: "banana", ExternalRef: "mda-" + uuid.NewString()}, // invalid enum → failed
		{Name: "NoRef"}, // missing external_ref → failed
		{Name: "Good2", ExternalRef: "mda-" + uuid.NewString()},
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if res.Created != 2 || res.Failed != 2 {
		t.Fatalf("valid rows must still create around the bad ones: created=%d failed=%d", res.Created, res.Failed)
	}
	if res.Results[1].Status != "failed" || res.Results[2].Status != "failed" {
		t.Fatalf("the bad rows must be reported failed, got %q / %q", res.Results[1].Status, res.Results[2].Status)
	}
}

func TestCreateBatch_CapAndEmpty(t *testing.T) {
	svc, _ := batchSvc(t)
	ctx := context.Background()
	if _, err := svc.CreateBatch(ctx, nil); err == nil {
		t.Fatal("empty batch must be rejected")
	}
	big := make([]tenant.BatchRow, 101)
	for i := range big {
		big[i] = tenant.BatchRow{Name: "x", ExternalRef: uuid.NewString()}
	}
	if _, err := svc.CreateBatch(ctx, big); err == nil {
		t.Fatal("over-cap batch must be rejected wholesale (ONB-3)")
	}
}
