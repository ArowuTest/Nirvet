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

	"github.com/ArowuTest/nirvet/internal/alert"
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

// MA-2/3 #4: a fleet write lands the MUTATION in the TARGET tenant AND a DEDICATED audit entry in the TARGET
// tenant with the OPERATOR's real identity — so the agency sees who acted on its resource. A non-provider has
// no write path.
func TestFleetWrite_Assign_LandsInTargetWithOperatorIdentity(t *testing.T) {
	db := fleetDB(t)
	svc := NewService(db).WithAlerts(alert.NewService(alert.NewRepository(db)))
	ctx := context.Background()

	tA := mkTenant(t, db)
	alertID := mkAlertID(t, db, tA)
	op := auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RoleSOCManager, Email: "op@venture"}

	if err := svc.AssignAlert(ctx, op, alertID, op.UserID); err != nil {
		t.Fatalf("fleet assign: %v", err)
	}

	// The mutation landed in the TARGET tenant (tA): the alert is now assigned to the operator.
	var assignee *uuid.UUID
	var auditActor *uuid.UUID
	var auditAction string
	if err := db.WithTenant(ctx, tA, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT assignee_id FROM alerts WHERE id=$1`, alertID).Scan(&assignee); e != nil {
			return e
		}
		// The dedicated audit entry landed in the TARGET tenant (tA) with the operator's identity.
		return tx.QueryRow(ctx,
			`SELECT actor_id, action FROM audit_log WHERE target=$1 AND action='fleet.alert.assign' ORDER BY at DESC LIMIT 1`,
			"alert:"+alertID.String()).Scan(&auditActor, &auditAction)
	}); err != nil {
		t.Fatalf("verify target tenant state: %v", err)
	}
	if assignee == nil || *assignee != op.UserID {
		t.Fatalf("mutation must land in the target tenant (alert assigned to the operator), got %v", assignee)
	}
	if auditActor == nil || *auditActor != op.UserID {
		t.Fatalf("audit must land in the TARGET tenant with the OPERATOR's identity, got actor %v action %q", auditActor, auditAction)
	}

	// A non-provider has NO write path — the assign is refused, and nothing is written.
	cust := auth.Principal{UserID: uuid.New(), TenantID: tA, Role: auth.RoleCustomerAdmin, Email: "c@mda"}
	if err := svc.AssignAlert(ctx, cust, alertID, cust.UserID); err == nil {
		t.Fatal("a non-provider MUST NOT be able to perform a fleet write")
	}
}
