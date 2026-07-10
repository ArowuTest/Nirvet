package fleet

// MA-1 — the single highest-consequence line in the operator reframe. fleet_alerts is a SECURITY DEFINER fn
// with RLS inert inside (superuser definer), so its `tenant_id = ANY($set)` is the ONLY guard. This test proves
// the two properties a bug here would break: (1) scoped → ONLY the set's tenants (never a leak), and (2) the
// catastrophic case — an empty or NULL scope returns ZERO rows, never all tenants.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func fleetDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func mkTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "fleet-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func mkAlert(t *testing.T, db *database.DB, tid uuid.UUID, title string) {
	t.Helper()
	// tenant_id defaults to app_current_tenant() under WithTenant(tid).
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO alerts (id, title, severity, status, source) VALUES ($1,$2,'high','new','test')`, uuid.New(), title)
		return e
	})
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
}

func TestFleetAlerts_MA1_ScopedAndFailClosed(t *testing.T) {
	db := fleetDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	tA, tB := mkTenant(t, db), mkTenant(t, db)
	mkAlert(t, db, tA, "a-alert")
	mkAlert(t, db, tB, "b-alert")

	// scoped to {tA} → ONLY tA's alert, never tB's (the BOLA line).
	got, err := repo.FleetAlerts(ctx, []uuid.UUID{tA}, "", 100)
	if err != nil {
		t.Fatalf("scoped read: %v", err)
	}
	if len(got) != 1 || got[0].TenantID != tA {
		t.Fatalf("scope {tA} must return ONLY tA's alerts (1), got %d: %+v", len(got), got)
	}
	for _, a := range got {
		if a.TenantID == tB {
			t.Fatal("BOLA: scope {tA} leaked tenant B's alert")
		}
	}

	// scoped to {tA,tB} → both.
	got, err = repo.FleetAlerts(ctx, []uuid.UUID{tA, tB}, "", 100)
	if err != nil {
		t.Fatalf("two-tenant read: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("scope {tA,tB} must return both tenants' alerts, got %d", len(got))
	}

	// FAIL CLOSED — empty scope → ZERO rows (never all). If broken it returns every alert in the DB.
	got, err = repo.FleetAlerts(ctx, []uuid.UUID{}, "", 100)
	if err != nil {
		t.Fatalf("empty-scope read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("MA-1 FAIL-CLOSED VIOLATED: empty scope returned %d rows (must be 0 — a leak of the whole fleet)", len(got))
	}

	// FAIL CLOSED — NULL scope → ZERO rows.
	got, err = repo.FleetAlerts(ctx, nil, "", 100)
	if err != nil {
		t.Fatalf("nil-scope read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("MA-1 FAIL-CLOSED VIOLATED: nil scope returned %d rows (must be 0)", len(got))
	}

	// status filter narrows within the scope (sanity — no widening).
	got, err = repo.FleetAlerts(ctx, []uuid.UUID{tA}, "resolved", 100)
	if err != nil {
		t.Fatalf("status-filtered read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("status filter should exclude the 'new' alert, got %d", len(got))
	}
}
