package main

import (
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
