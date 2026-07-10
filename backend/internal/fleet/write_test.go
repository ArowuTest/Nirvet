package fleet

// MA-2/3 write path — target resolution, the foundation of the highest-consequence surface (a wrong target =
// a containment action on the wrong government agency). This proves reviewer points #1+#2 on the target gate:
//   - TARGET-FROM-RESOURCE: the target tenant is the ALERT ROW's tenant — even when the operator's own
//     principal carries a DIFFERENT tenant, and it can't be redirected by a forged id.
//   - FLEET-SCOPE CHECK / no write for non-providers: a non-provider's empty scope → refused for every alert,
//     so a non-oversight principal has NO cross-tenant write path; a forged/nonexistent id is refused (no leak).

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func mkAlertID(t *testing.T, db *database.DB, tid uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO alerts (id, title, severity, status, source) VALUES ($1,'w','high','new','test')`, id)
		return e
	})
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return id
}

func TestFleetWrite_TargetResolution_MA2(t *testing.T) {
	db := fleetDB(t)
	svc := NewService(db)
	ctx := context.Background()

	tA := mkTenant(t, db)
	alertID := mkAlertID(t, db, tA)
	tB := mkTenant(t, db) // the operator's OWN tenant — deliberately different from the alert's tenant.

	// (1) TARGET-FROM-RESOURCE: a provider operator whose own principal carries tB resolves the target to the
	// ALERT's tenant (tA), NOT their own. The target comes from the row, never from p.TenantID.
	op := auth.Principal{UserID: uuid.New(), TenantID: tB, Role: auth.RoleSOCManager}
	target, err := svc.ResolveTargetTenant(ctx, op, alertID)
	if err != nil {
		t.Fatalf("provider target resolve: %v", err)
	}
	if target != tA {
		t.Fatalf("target MUST be the alert's tenant (tA=%s), not the operator's own (tB=%s), got %s", tA, tB, target)
	}

	// (2) NON-PROVIDER → EMPTY scope → NO write path: a customer_admin (even of tA, which owns the alert) is
	// refused. A non-oversight principal has no cross-tenant write path at all.
	cust := auth.Principal{UserID: uuid.New(), TenantID: tA, Role: auth.RoleCustomerAdmin}
	if _, err := svc.ResolveTargetTenant(ctx, cust, alertID); err == nil {
		t.Fatal("MA-2: a non-provider principal MUST have no write path (expected refusal), got nil error")
	}

	// (3) FORGED / nonexistent alert id → refused (no crash, no leak; indistinct from out-of-scope, no oracle).
	if _, err := svc.ResolveTargetTenant(ctx, op, uuid.New()); err == nil {
		t.Fatal("MA-2: a forged/nonexistent alert id MUST be refused, got nil error")
	}
}
