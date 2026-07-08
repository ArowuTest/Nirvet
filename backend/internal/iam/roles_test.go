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
