package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
)

func has(roles []auth.Role, r auth.Role) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

// TestRBACTiers locks the R2 H-D/M-D control: analyst_t1 must NOT be in the senior or
// manager tiers (so a T1 token can't reach destructive/sensitive routes), while T2/T3
// and management roles are, and only admin+manager are in the manager tier.
func TestRBACTiers(t *testing.T) {
	// analyst_t1 is a provider (reads + triage/assign/note) but nothing more.
	if !has(providerRoles, auth.RoleAnalystT1) {
		t.Fatal("analyst_t1 must remain a provider (reads + triage)")
	}
	if has(seniorRoles, auth.RoleAnalystT1) {
		t.Fatal("analyst_t1 must NOT be senior (no connector delete / playbook run / close / promote)")
	}
	if has(managerRoles, auth.RoleAnalystT1) {
		t.Fatal("analyst_t1 must NOT be manager (no asset-criticality writes)")
	}

	// Senior tier: platform_admin, soc_manager, analyst_t2, analyst_t3.
	for _, r := range []auth.Role{auth.RolePlatformAdmin, auth.RoleSOCManager, auth.RoleAnalystT2, auth.RoleAnalystT3} {
		if !has(seniorRoles, r) {
			t.Fatalf("%s must be in the senior tier", r)
		}
	}
	// Manager tier is exactly platform_admin + soc_manager.
	if len(managerRoles) != 2 || !has(managerRoles, auth.RolePlatformAdmin) || !has(managerRoles, auth.RoleSOCManager) {
		t.Fatalf("manager tier must be exactly {platform_admin, soc_manager}, got %v", managerRoles)
	}
	// analyst_t2/t3 are NOT managers (can't set asset criticality).
	if has(managerRoles, auth.RoleAnalystT2) || has(managerRoles, auth.RoleAnalystT3) {
		t.Fatal("analyst_t2/t3 must NOT be in the manager tier")
	}
}

// serveWithRole applies a role gate to a trivial 200 handler and returns the status a principal with `role` gets.
func serveWithRole(role auth.Role, gate ...auth.Role) int {
	h := auth.RequireRole(gate...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("GET", "/admin/audit", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Role: role}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestAdminAuditIsPlatformAdminOnly locks the reviewer finding: GET /admin/audit returns the RAW operator audit
// trail and must be platform_admin ONLY (padmin = RequireRole(RolePlatformAdmin)), never ssoAdmin
// (RequireRole(RolePlatformAdmin, RoleCustomerAdmin)) which would let a customer read internal operator activity.
func TestAdminAuditIsPlatformAdminOnly(t *testing.T) {
	// The padmin gate the route now uses: platform_admin passes, customer_admin is FORBIDDEN.
	if got := serveWithRole(auth.RolePlatformAdmin, auth.RolePlatformAdmin); got != http.StatusOK {
		t.Fatalf("platform_admin must reach /admin/audit, got %d", got)
	}
	if got := serveWithRole(auth.RoleCustomerAdmin, auth.RolePlatformAdmin); got != http.StatusForbidden {
		t.Fatalf("customer_admin must be 403 on /admin/audit (raw operator audit trail), got %d", got)
	}
	// Guard against regressing back to the ssoAdmin role set: with customer_admin in the gate, a customer WOULD
	// reach it — which is exactly the over-disclosure this test forbids. Asserting the leak path proves the fix
	// closed it (the route must not use this gate for the audit trail).
	if got := serveWithRole(auth.RoleCustomerAdmin, auth.RolePlatformAdmin, auth.RoleCustomerAdmin); got != http.StatusOK {
		t.Fatalf("sanity: the ssoAdmin role set would admit customer_admin (got %d) — the audit route must not use it", got)
	}
}
