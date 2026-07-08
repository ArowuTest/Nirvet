package iam

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
)

// TestValidateGrantableRole locks the Round-4 H1 fix: the provider/customer domain guard that
// service-account + invitation creation share. A customer-side actor may NOT grant a provider (SOC)
// role; provider actors may grant customer roles; platform_admin and unknown roles are never grantable.
func TestValidateGrantableRole(t *testing.T) {
	cases := []struct {
		name          string
		actor, target auth.Role
		wantErr       bool
	}{
		{"customer_admin mints soc_manager (H1)", auth.RoleCustomerAdmin, auth.RoleSOCManager, true},
		{"customer_admin mints analyst_t3", auth.RoleCustomerAdmin, auth.RoleAnalystT3, true},
		{"customer_admin mints detection_eng", auth.RoleCustomerAdmin, auth.RoleDetectionEng, true},
		{"customer_admin mints customer_viewer (same domain, ok)", auth.RoleCustomerAdmin, auth.RoleCustomerViewer, false},
		{"platform_admin grants soc_manager (provider→provider, ok)", auth.RolePlatformAdmin, auth.RoleSOCManager, false},
		{"soc_manager grants customer_admin (provider→customer, ok)", auth.RoleSOCManager, auth.RoleCustomerAdmin, false},
		{"nobody grants platform_admin", auth.RolePlatformAdmin, auth.RolePlatformAdmin, true},
		{"unknown target role rejected", auth.RoleCustomerAdmin, auth.Role("wizard"), true},
	}
	for _, c := range cases {
		err := validateGrantableRole(c.actor, c.target)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateGrantableRole(%s,%s) err=%v, wantErr=%v", c.name, c.actor, c.target, err, c.wantErr)
		}
	}
}

// TestBreakGlassEligible locks the Round-4 M5 eligibility floor: provider roles and customer_admin
// may invoke break-glass; a read-only customer_viewer (and unknown roles) may not.
func TestBreakGlassEligible(t *testing.T) {
	for _, r := range []auth.Role{auth.RoleAnalystT1, auth.RoleSOCManager, auth.RoleDetectionEng, auth.RoleCustomerAdmin} {
		if !breakGlassEligible(r) {
			t.Errorf("%s should be break-glass eligible", r)
		}
	}
	for _, r := range []auth.Role{auth.RoleCustomerViewer, auth.Role("wizard")} {
		if breakGlassEligible(r) {
			t.Errorf("%s must NOT be break-glass eligible", r)
		}
	}
	// The one-tier cap (enforced in BreakGlass) rests on the canonical rank: analyst_t1 → soc_manager
	// is a 3-tier jump and must be rejected; analyst_t1 → analyst_t2 is one tier and allowed.
	if auth.RoleRank(auth.RoleSOCManager) <= auth.RoleRank(auth.RoleAnalystT1)+1 {
		t.Fatal("analyst_t1 → soc_manager must exceed the one-tier break-glass cap")
	}
	if auth.RoleRank(auth.RoleAnalystT2) > auth.RoleRank(auth.RoleAnalystT1)+1 {
		t.Fatal("analyst_t1 → analyst_t2 should be within the one-tier cap")
	}
}
