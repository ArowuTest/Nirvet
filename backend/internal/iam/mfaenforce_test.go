package iam

// S1 force-MFA tests (gate §5). Two layers:
//   1. TestMFARoleRequired — the PURE decision (floor ∪ tenant scope + zero-config), no DB. Covers the operator
//      floor (all-roles, role-list, tighten-only) WITHOUT mutating the global mfa_enforcement_floor singleton, which
//      would race cross-package integration tests on the shared CI DB.
//   2. TestForceMFA_TenantEnforcement — the DB wiring, driven by the TENANT-scoped session_policies only (no global
//      floor touched). Proves MintSession reads the policy and REFUSES a full session for an in-scope no-MFA user,
//      while the grace mint succeeds. Mutation-sensitive: neutralise the MintSession enforcement → RED.

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

func TestMFARoleRequired(t *testing.T) {
	viewer := string(auth.RoleCustomerViewer)
	admin := string(auth.RolePlatformAdmin)
	cases := []struct {
		name          string
		role          auth.Role
		tenantRequire bool
		tenantRoles   []string
		floorAll      bool
		floorRoles    []string
		want          bool
	}{
		{"no policy → not required", auth.RoleCustomerViewer, false, nil, false, nil, false},
		{"operator floor all-roles → any role required", auth.RoleCustomerViewer, false, nil, true, nil, true},
		{"operator floor all-roles → admin required", auth.RolePlatformAdmin, false, nil, true, nil, true},
		{"floor role-list hits", auth.RolePlatformAdmin, false, nil, false, []string{admin}, true},
		{"floor role-list misses other role", auth.RoleCustomerViewer, false, nil, false, []string{admin}, false},
		{"tenant policy adds a role", auth.RoleCustomerViewer, true, []string{viewer}, false, nil, true},
		{"tenant policy other role not required", auth.RoleSOCManager, true, []string{viewer}, false, nil, false},
		{"zero-config floor → privileged required", auth.RolePlatformAdmin, true, nil, false, nil, true},
		{"zero-config floor → viewer NOT required", auth.RoleCustomerViewer, true, nil, false, nil, false},
		{"tighten-only: floor wins over tenant-off", auth.RoleAnalystT1, false, nil, false, []string{string(auth.RoleAnalystT1)}, true},
	}
	for _, c := range cases {
		if got := mfaRoleRequired(c.role, c.tenantRequire, c.tenantRoles, c.floorAll, c.floorRoles); got != c.want {
			t.Errorf("%s: mfaRoleRequired=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestForceMFA_TenantEnforcement(t *testing.T) {
	db := genDB(t)
	svc := genSvc(t, db)
	ctx := context.Background()

	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "mfa-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tn.ID

	// TENANT-scoped policy only — never touches the global mfa_enforcement_floor (no cross-package pollution).
	setTenantMFA := func(require bool, roles []string) {
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
	mkUser := func(role auth.Role, mfaOn bool) auth.Principal {
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
		gp := p // grace (MFAPending) mint is the escape hatch — MUST succeed so the user can enroll.
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

	// Tenant requires MFA for customer_viewer.
	setTenantMFA(true, []string{string(auth.RoleCustomerViewer)})
	// In-scope, no MFA → refused (mutation-sensitive: neutralise the MintSession enforcement → RED).
	mustRefuse("in-scope no-MFA", mkUser(auth.RoleCustomerViewer, false))
	// In-scope but enrolled → full session.
	mustAllow("in-scope enrolled", mkUser(auth.RoleCustomerViewer, true))
	// Out-of-scope role (not in the tenant list, floor off) → full session, no regression.
	mustAllow("out-of-scope role", mkUser(auth.RoleSOCManager, false))
	// Policy off entirely → full session.
	setTenantMFA(false, nil)
	mustAllow("policy off", mkUser(auth.RoleCustomerViewer, false))
}
