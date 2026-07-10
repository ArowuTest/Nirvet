package posture_test

// MA-4 vendor posture oversight — the read/authz/store invariants against a migrated Postgres.
//   - Vendor (platform_admin) sees fleet-wide METADATA; a non-vendor principal fail-closes to empty.
//   - The dedicated SD function fail-closes (empty/NULL scope → 0 rows) and is BOLA-bounded to the scope set.
//   - Storage twin (MA4-5): the tenant_posture table has NO free-text/jsonb column — content is unstorable.
// (The structural no-import-path invariant is proven by scripts/check-posture-no-content-import.sh, run in CI.)

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/posture"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func postureDB(t *testing.T) *database.DB {
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
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "pos-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.ID
}

func find(rows []posture.Posture, id uuid.UUID) *posture.Posture {
	for i := range rows {
		if rows[i].TenantID == id {
			return &rows[i]
		}
	}
	return nil
}

func TestPostureFleet_VendorSeesMetadata_NonVendorEmpty(t *testing.T) {
	db := postureDB(t)
	svc := posture.NewService(db)
	ctx := context.Background()

	tA := mkTenant(t, db)
	tB := mkTenant(t, db)
	if err := svc.Record(ctx, tA, posture.Metrics{OpenTotal: 3, OpenCritical: 1, SLABreached: 2, AckOverdue: 1}); err != nil {
		t.Fatalf("record tA: %v", err)
	}
	if err := svc.Record(ctx, tB, posture.Metrics{OpenTotal: 1}); err != nil {
		t.Fatalf("record tB: %v", err)
	}

	// Vendor platform_admin sees the fleet, including tA's metadata.
	admin := auth.Principal{UserID: uuid.New(), TenantID: tA, Role: auth.RolePlatformAdmin, Email: "vendor@op"}
	rows, err := svc.Fleet(ctx, admin)
	if err != nil {
		t.Fatalf("vendor fleet read: %v", err)
	}
	a := find(rows, tA)
	if a == nil || a.OpenTotal != 3 || a.OpenCritical != 1 || a.SLABreached != 2 || a.AckOverdue != 1 {
		t.Fatalf("vendor must see tA's posture metadata, got %+v", a)
	}
	if find(rows, tB) == nil {
		t.Fatal("vendor must see the whole fleet (tB present)")
	}

	// A non-vendor provider (soc_manager) and a customer_admin BOTH fail-closed to empty — the vendor seat is
	// platform_admin; deriving scope from the principal means "who's the vendor" fails CLOSED.
	for _, role := range []auth.Role{auth.RoleSOCManager, auth.RoleCustomerAdmin, auth.RoleAnalystT2, ""} {
		p := auth.Principal{UserID: uuid.New(), TenantID: tA, Role: role}
		got, err := svc.Fleet(ctx, p)
		if err != nil {
			t.Fatalf("non-vendor fleet read (role %q): %v", role, err)
		}
		if len(got) != 0 {
			t.Fatalf("a non-vendor principal (role %q) MUST see zero posture rows, got %d", role, len(got))
		}
	}
}

func TestPostureSDFn_FailClosed_AndBounded(t *testing.T) {
	db := postureDB(t)
	repo := posture.NewRepository(db)
	ctx := context.Background()
	tA := mkTenant(t, db)
	tB := mkTenant(t, db)
	_ = repo.Upsert(ctx, tA, posture.Metrics{OpenTotal: 5})
	_ = repo.Upsert(ctx, tB, posture.Metrics{OpenTotal: 7})

	// Fail-closed: empty and NULL scope → ZERO rows, never all (even though rows exist).
	if out, err := repo.FleetPosture(ctx, nil); err != nil || len(out) != 0 {
		t.Fatalf("nil scope MUST return 0 rows (fail-closed), got %d (err %v)", len(out), err)
	}
	if out, err := repo.FleetPosture(ctx, []uuid.UUID{}); err != nil || len(out) != 0 {
		t.Fatalf("empty scope MUST return 0 rows (fail-closed), got %d (err %v)", len(out), err)
	}
	// Bounded: scope {tA} returns tA's row and NOT tB's (the SD-fn's tenant_id = ANY($set) is the only guard).
	out, err := repo.FleetPosture(ctx, []uuid.UUID{tA})
	if err != nil {
		t.Fatalf("scoped read: %v", err)
	}
	if find(out, tA) == nil || find(out, tB) != nil {
		t.Fatalf("scope {tA} must return ONLY tA's row, got %d rows including tB=%v", len(out), find(out, tB) != nil)
	}
}

// TestTenantPosture_StorageTwin_NoContentColumn (MA4-5): the store itself cannot hold content — every column
// is an int / timestamp / uuid. A buggy projector has nowhere to put a title/description/category.
func TestTenantPosture_StorageTwin_NoContentColumn(t *testing.T) {
	db := postureDB(t)
	ctx := context.Background()
	var bad []string
	err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT column_name, data_type FROM information_schema.columns WHERE table_name='tenant_posture'`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var name, dtype string
			if e := rows.Scan(&name, &dtype); e != nil {
				return e
			}
			switch dtype {
			case "text", "character varying", "character", "json", "jsonb", "bytea":
				bad = append(bad, name+":"+dtype)
			}
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read information_schema: %v", err)
	}
	if len(bad) != 0 {
		t.Fatalf("MA4-5 storage twin violated — tenant_posture has free-text/jsonb columns that could hold content: %v", bad)
	}
}
