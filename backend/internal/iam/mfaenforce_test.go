package iam

// S1 force-MFA — DB-gated, mutation-sensitive enforcement tests (gate §5, the close-out bar). Enforcement is at the
// MintSession chokepoint (covers password/SSO/refresh), so these exercise MintSession directly. Each test sets the
// operator floor explicitly, so they are order-independent (the floor is a global singleton) and never depend on
// the seeded default. Reuses genDB/genSvc from session_generation_test.go.
//
// The load-bearing assertion: an in-scope, no-MFA user is REFUSED a full session (auth.ErrMFAEnrollmentRequired),
// while the MFAPending grace mint succeeds. Removing the enforcement block in MintSession makes the refusal
// disappear → these go RED (the exact mfa.enforce regression).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestForceMFA_Enforcement(t *testing.T) {
	db := genDB(t)
	svc := genSvc(t, db)
	ctx := context.Background()

	newTenant := func() uuid.UUID {
		t.Helper()
		tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "mfa-" + uuid.NewString()})
		if err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		return tn.ID
	}
	setFloor := func(all bool, roles []string) {
		t.Helper()
		if roles == nil {
			roles = []string{}
		}
		if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE mfa_enforcement_floor SET require_all_roles=$1, floor_roles=$2 WHERE id=1`, all, roles)
			return e
		}); err != nil {
			t.Fatalf("set floor: %v", err)
		}
	}
	setTenantMFA := func(tid uuid.UUID, require bool, roles []string) {
		t.Helper()
		if roles == nil {
			roles = []string{}
		}
		if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `INSERT INTO session_policies (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, tid); e != nil {
				return e
			}
			_, e := tx.Exec(ctx, `UPDATE session_policies SET require_mfa=$2, mfa_required_roles=$3 WHERE tenant_id=$1`, tid, require, roles)
			return e
		}); err != nil {
			t.Fatalf("set tenant mfa: %v", err)
		}
	}
	mkUser := func(tid uuid.UUID, role auth.Role, mfaOn bool) auth.Principal {
		t.Helper()
		uid := uuid.New()
		if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, password_hash, role, status, mfa_enabled)
				VALUES ($1,$2,$3,'x',$4,$5,$6)`, uid, tid, uid.String()+"@mfa.test", string(role), string(UserActive), mfaOn)
			return e
		}); err != nil {
			t.Fatalf("mk user: %v", err)
		}
		return auth.Principal{UserID: uid, TenantID: tid, Role: role, Email: uid.String() + "@mfa.test"}
	}
	mustRefuse := func(name string, p auth.Principal) {
		t.Helper()
		if _, err := svc.MintSession(ctx, &p, time.Hour); !errors.Is(err, auth.ErrMFAEnrollmentRequired) {
			t.Fatalf("%s: expected ErrMFAEnrollmentRequired, got %v", name, err)
		}
		gp := p // the grace (MFAPending) mint is the escape hatch — it MUST succeed so the user can enroll.
		gp.MFAPending = true
		if _, err := svc.MintSession(ctx, &gp, time.Hour); err != nil {
			t.Fatalf("%s: grace mint must succeed, got %v", name, err)
		}
	}
	mustAllow := func(name string, p auth.Principal) {
		t.Helper()
		if _, err := svc.MintSession(ctx, &p, time.Hour); err != nil {
			t.Fatalf("%s: expected a full session, got %v", name, err)
		}
	}
	tid := newTenant()

	// 1. Operator floor = ALL roles → any in-scope no-MFA user is refused. Mutation-sensitive: remove the
	//    enforcement block in MintSession → mustRefuse's first mint returns no error → RED. customer_viewer proves
	//    it is not privileged-only.
	setFloor(true, nil)
	setTenantMFA(tid, false, nil)
	mustRefuse("all-roles floor / viewer", mkUser(tid, auth.RoleCustomerViewer, false))
	mustRefuse("all-roles floor / admin", mkUser(tid, auth.RolePlatformAdmin, false))

	// 2. An enrolled user (mfa_enabled=true) is unaffected — full session even under the all-roles floor.
	mustAllow("enrolled user", mkUser(tid, auth.RoleCustomerViewer, true))

	// 3. Floor OFF + tenant OFF = unchanged legacy behaviour: a no-MFA user gets a full session (no regression).
	setFloor(false, nil)
	setTenantMFA(tid, false, nil)
	mustAllow("no policy", mkUser(tid, auth.RoleSOCManager, false))

	// 4. Zero-config floor (2d): tenant require_mfa=true with an EMPTY role scope enforces PRIVILEGED roles, never
	//    "no one" — a privileged no-MFA user is refused; a non-privileged one is not.
	setFloor(false, nil)
	setTenantMFA(tid, true, nil)
	mustRefuse("zero-config / privileged", mkUser(tid, auth.RolePlatformAdmin, false))
	mustAllow("zero-config / non-privileged", mkUser(tid, auth.RoleCustomerViewer, false))

	// 5. Tighten-only: the operator floor wins even when the tenant policy is OFF — a tenant can never drop below
	//    the floor. Floor=all-roles, tenant require_mfa=false → a no-MFA user is still refused.
	setFloor(true, nil)
	setTenantMFA(tid, false, nil)
	mustRefuse("floor tightens-only", mkUser(tid, auth.RoleAnalystT1, false))

	// Reset the singleton floor OFF so other iam integration tests (which mint no-MFA users) are unaffected.
	setFloor(false, nil)
}
