package platformadmin

// §6.18 #122 P-3 — tenant lifecycle + uniform offboarding: legal-hold BLOCKS delete, clearing a hold needs the
// elevated envelope (M-3), and delete purges every tenant-scoped table + issues a certificate of destruction.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func seedTenantRow(t *testing.T, db *database.DB, tid uuid.UUID) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO connector_configs (id, tenant_id, kind, name, direction, enabled, config, health)
			VALUES (gen_random_uuid(),$1,'webhook','x','push',true,'{}','unknown')`, tid)
		return e
	}); err != nil {
		t.Fatalf("seed connector: %v", err)
	}
}

func tenantRowCount(t *testing.T, db *database.DB, tid uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM connector_configs WHERE tenant_id=$1`, tid).Scan(&n)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestLifecycle_LegalHoldBlocksDelete(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedTenantRow(t, db, tid)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	a := padminActor()
	ctx := context.Background()

	if err := svc.SetLegalHold(ctx, a, tid, "regulatory investigation"); err != nil {
		t.Fatalf("set hold: %v", err)
	}
	// Even with a full elevated envelope, a hold blocks the purge (legal_hold is checked FIRST in the function).
	approver := uuid.New()
	if _, err := svc.OffboardTenant(ctx, a, tid, "customer left", &approver); status(err) != 403 {
		t.Fatalf("delete under legal hold must be refused (403), got %v", err)
	}
	if tenantRowCount(t, db, tid) != 1 {
		t.Fatal("data must be preserved while on legal hold")
	}
}

// markExportedElapsed puts a tenant into the exported state with its retention window already elapsed, so an
// otherwise-valid offboard can proceed.
func markExportedElapsed(t *testing.T, db *database.DB, svc *Service, tid uuid.UUID) {
	t.Helper()
	if err := svc.MarkExported(context.Background(), padminActor(), tid, "data exported to customer"); err != nil {
		t.Fatalf("mark exported: %v", err)
	}
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET exported_at = now() - interval '400 days' WHERE id=$1`, tid)
		return e
	}); err != nil {
		t.Fatalf("age export: %v", err)
	}
}

// H-1: OffboardTenant carries the SAME elevated envelope as ClearLegalHold — no distinct approver → 403, never a
// single-padmin irreversible purge.
func TestLifecycle_OffboardNeedsFourEyes(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedTenantRow(t, db, tid)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	markExportedElapsed(t, db, svc, tid)
	// No approver → refused (four-eyes) even though the tenant is exported + retention-elapsed.
	if _, err := svc.OffboardTenant(context.Background(), padminActor(), tid, "customer left", nil); status(err) != 403 {
		t.Fatalf("offboard without four-eyes must be 403, got %v", err)
	}
	if tenantRowCount(t, db, tid) != 1 {
		t.Fatal("data must be preserved when the envelope is incomplete")
	}
}

// H-1: a purge is refused unless the tenant is in the 'exported' state — never straight from active.
func TestLifecycle_OffboardRefusedFromActiveState(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedTenantRow(t, db, tid)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	approver := uuid.New()
	// Full envelope, but the tenant was never exported → 409 conflict, data preserved.
	if _, err := svc.OffboardTenant(context.Background(), padminActor(), tid, "customer left", &approver); status(err) != 409 {
		t.Fatalf("offboard from a non-exported state must be 409, got %v", err)
	}
	if tenantRowCount(t, db, tid) != 1 {
		t.Fatal("data must be preserved when the tenant is not exported")
	}
}

// H-1: a purge is refused until the retention window has elapsed.
func TestLifecycle_OffboardRefusedBeforeRetention(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedTenantRow(t, db, tid)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	if err := svc.MarkExported(context.Background(), padminActor(), tid, "exported"); err != nil {
		t.Fatalf("mark exported: %v", err)
	}
	approver := uuid.New()
	// exported_at is now() (default 30-day retention not elapsed) → 409, data preserved.
	if _, err := svc.OffboardTenant(context.Background(), padminActor(), tid, "customer left", &approver); status(err) != 409 {
		t.Fatalf("offboard before retention elapses must be 409, got %v", err)
	}
	if tenantRowCount(t, db, tid) != 1 {
		t.Fatal("data must be preserved before the retention window elapses")
	}
}

func TestLifecycle_ClearHoldNeedsFourEyes(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	al := &mockPAAlerter{}
	svc := NewService(NewRepository(db), al)
	a := padminActor()
	ctx := context.Background()
	if err := svc.SetLegalHold(ctx, a, tid, "hold"); err != nil {
		t.Fatalf("set hold: %v", err)
	}
	// M-3: clearing a hold needs the elevated envelope — no distinct approver → 403.
	if err := svc.ClearLegalHold(ctx, a, tid, "done", nil); status(err) != 403 {
		t.Fatalf("clearing a hold without four-eyes must be 403, got %v", err)
	}
	approver := uuid.New()
	if err := svc.ClearLegalHold(ctx, a, tid, "investigation closed", &approver); err != nil {
		t.Fatalf("clear with four-eyes should succeed: %v", err)
	}
	if al.n != 1 {
		t.Fatalf("clearing a hold must raise one HIGH alert, got %d", al.n)
	}
	if held, _ := NewRepository(db).IsLegalHold(ctx, tid); held {
		t.Fatal("hold should be cleared")
	}
}

func TestLifecycle_OffboardPurgesAndCerts(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedTenantRow(t, db, tid)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	ctx := context.Background()

	// H-1: offboard now requires exported state + retention elapsed + the four-eyes envelope.
	markExportedElapsed(t, db, svc, tid)
	approver := uuid.New()
	cert, err := svc.OffboardTenant(ctx, padminActor(), tid, "contract ended", &approver)
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if len(cert) != 64 {
		t.Fatalf("expected a sha256 certificate of destruction, got %q", cert)
	}
	if tenantRowCount(t, db, tid) != 0 {
		t.Fatal("the uniform purge must delete the tenant's data")
	}
	// The tenant row is retained + marked deleted; the offboarding evidence (delete record) survives the purge.
	var stStatus string
	var purged int
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1`, tid).Scan(&stStatus); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `SELECT tables_purged FROM tenant_offboarding WHERE tenant_id=$1 AND action='delete'`, tid).Scan(&purged)
	}); err != nil {
		t.Fatalf("read post-state: %v", err)
	}
	if stStatus != "deleted" {
		t.Fatalf("tenant should be marked deleted, got %q", stStatus)
	}
	if purged < 1 {
		t.Fatalf("purge should have covered tenant-scoped tables, got %d", purged)
	}
}
