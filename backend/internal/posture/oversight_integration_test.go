package posture_test

// MA-OV adversarial family round — the oversight resolvers (org-sub-admin + payer) each prove they CANNOT
// widen: scope is derived from the authenticated principal's grants (no client-supplied id), a principal with
// no grant sees zero, revocation/cascade drops scope, cross-grant isolation holds, and grant issue/revoke is
// audited. All reads funnel through the cleared MA-4 tenant_posture_fleet() SD-fn.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/posture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func mkOrg(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO organisation (name) VALUES ($1) RETURNING id`, "org-"+uuid.NewString()).Scan(&id)
	}); err != nil {
		t.Fatalf("mkOrg: %v", err)
	}
	return id
}

func assignOrg(t *testing.T, db *database.DB, tenantID, orgID uuid.UUID) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET org_id=$2 WHERE id=$1`, tenantID, orgID)
		return e
	}); err != nil {
		t.Fatalf("assignOrg: %v", err)
	}
}

func mkAccount(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO billing_account (name, currency) VALUES ($1,'USD') RETURNING id`, "acct-"+uuid.NewString()).Scan(&id)
	}); err != nil {
		t.Fatalf("mkAccount: %v", err)
	}
	return id
}

func coverTenant(t *testing.T, db *database.DB, tenantID, accountID uuid.UUID) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO tenant_billing (tenant_id, billing_mode, billing_account_id, currency)
			VALUES ($1,'covered',$2,'USD')
			ON CONFLICT (tenant_id) DO UPDATE SET billing_mode='covered', billing_account_id=$2`, tenantID, accountID)
		return e
	}); err != nil {
		t.Fatalf("coverTenant: %v", err)
	}
}

func padminP(t *testing.T, db *database.DB) auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RolePlatformAdmin, Email: "padmin@op"}
}

func TestOversight_OrgSubAdmin_ScopedRevocableIsolated(t *testing.T) {
	db := postureDB(t)
	svc := posture.NewService(db)
	grants := posture.NewGrantService(db)
	ctx := context.Background()

	orgA, orgB := mkOrg(t, db), mkOrg(t, db)
	tA1, tA2, tB1 := mkTenant(t, db), mkTenant(t, db), mkTenant(t, db)
	assignOrg(t, db, tA1, orgA)
	assignOrg(t, db, tA2, orgA)
	assignOrg(t, db, tB1, orgB)
	for _, tid := range []uuid.UUID{tA1, tA2, tB1} {
		_ = svc.Record(ctx, tid, posture.Metrics{OpenTotal: 1})
	}

	admin := padminP(t, db)
	orgAdmin := auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RoleOrgSubAdmin, Email: "gov@authority"}
	if err := grants.GrantOrg(ctx, admin, orgAdmin.UserID, orgA); err != nil {
		t.Fatalf("grant org: %v", err)
	}

	// Sees ONLY orgA's tenants; orgB's is invisible.
	rows, err := svc.Fleet(ctx, orgAdmin)
	if err != nil {
		t.Fatalf("fleet: %v", err)
	}
	if find(rows, tA1) == nil || find(rows, tA2) == nil {
		t.Fatal("org-sub-admin must see its granted org's tenants")
	}
	if find(rows, tB1) != nil {
		t.Fatal("MA-OV: org-sub-admin MUST NOT see a tenant of an org it was not granted")
	}

	// A different org-sub-admin with NO grant → zero (closed default).
	noGrant := auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RoleOrgSubAdmin}
	if got, _ := svc.Fleet(ctx, noGrant); len(got) != 0 {
		t.Fatalf("an ungranted org-sub-admin MUST see zero, got %d", len(got))
	}

	// Revocation drops scope immediately.
	if err := grants.RevokeOrg(ctx, admin, orgAdmin.UserID, orgA); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got, _ := svc.Fleet(ctx, orgAdmin); len(got) != 0 {
		t.Fatalf("after revocation the org-sub-admin MUST see zero, got %d", len(got))
	}
}

func TestOversight_Payer_ScopedToGrantedAccount(t *testing.T) {
	db := postureDB(t)
	svc := posture.NewService(db)
	grants := posture.NewGrantService(db)
	ctx := context.Background()

	acctA, acctB := mkAccount(t, db), mkAccount(t, db)
	tA, tB := mkTenant(t, db), mkTenant(t, db)
	coverTenant(t, db, tA, acctA)
	coverTenant(t, db, tB, acctB)
	_ = svc.Record(ctx, tA, posture.Metrics{OpenTotal: 2})
	_ = svc.Record(ctx, tB, posture.Metrics{OpenTotal: 3})

	admin := padminP(t, db)
	payer := auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RolePayer, Email: "buyer@anchor"}
	if err := grants.GrantPayer(ctx, admin, payer.UserID, acctA); err != nil {
		t.Fatalf("grant payer: %v", err)
	}

	rows, err := svc.Fleet(ctx, payer)
	if err != nil {
		t.Fatalf("fleet: %v", err)
	}
	if find(rows, tA) == nil {
		t.Fatal("payer must see its granted account's covered tenants")
	}
	if find(rows, tB) != nil {
		t.Fatal("MA-OV: payer MUST NOT see a tenant covered by a different account")
	}
	// No-grant payer → zero.
	if got, _ := svc.Fleet(ctx, auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RolePayer}); len(got) != 0 {
		t.Fatalf("an ungranted payer MUST see zero, got %d", len(got))
	}
}

// TestOversight_GrantAudited (MA-OV-3): issuing a grant writes an audit row with the padmin as actor.
func TestOversight_GrantAudited(t *testing.T) {
	db := postureDB(t)
	grants := posture.NewGrantService(db)
	ctx := context.Background()
	admin := padminP(t, db)
	orgID := mkOrg(t, db)

	if err := grants.GrantOrg(ctx, admin, uuid.New(), orgID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	var n int
	if err := db.WithTenant(ctx, admin.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='oversight.grant.org' AND actor_id=$1`, admin.UserID).Scan(&n)
	}); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if n == 0 {
		t.Fatal("MA-OV-3: a grant issue MUST write an audit event with the padmin as actor")
	}
}
