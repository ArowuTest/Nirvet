package sso

import "testing"

// A tenant SSO connection may only JIT-provision customer roles — never a
// provider/privileged role (privilege-escalation guard).
func TestValidSSORole(t *testing.T) {
	allowed := []string{"customer_viewer", "customer_admin"}
	for _, r := range allowed {
		if !ValidSSORole(r) {
			t.Errorf("%q should be an allowed SSO default_role", r)
		}
	}
	forbidden := []string{"platform_admin", "soc_manager", "analyst_t1", "analyst_t3", "detection_engineer", "", "root"}
	for _, r := range forbidden {
		if ValidSSORole(r) {
			t.Errorf("%q must NOT be an allowed SSO default_role (privilege escalation)", r)
		}
	}
}
