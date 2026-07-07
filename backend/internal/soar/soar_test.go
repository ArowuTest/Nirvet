package soar

import "testing"

// TestAuthorityMatrix locks the authority-to-act policy (doc 03 §6 / doc 04 §9.5):
// which risk classes may auto-execute (without approval) under each tenant mode.
func TestAuthorityMatrix(t *testing.T) {
	cases := []struct {
		mode AuthorityMode
		risk RiskClass
		want bool
	}{
		{AuthorityObserve, RiskLow, false},   // observe: nothing auto-runs
		{AuthorityObserve, RiskCritical, false},
		{AuthorityApproval, RiskLow, true},   // approval: only low auto-runs
		{AuthorityApproval, RiskMedium, false},
		{AuthorityApproval, RiskHigh, false},
		{AuthorityPreAuth, RiskLow, true},    // pre-auth: low + medium
		{AuthorityPreAuth, RiskMedium, true},
		{AuthorityPreAuth, RiskHigh, false},
		{AuthorityEmergency, RiskHigh, true}, // emergency: up to high
		{AuthorityEmergency, RiskCritical, false}, // NEVER auto-run critical
		{"bogus", RiskLow, false},            // unknown mode denies
	}
	for _, c := range cases {
		if got := Allowed(c.mode, c.risk); got != c.want {
			t.Errorf("Allowed(%s, %s) = %v, want %v", c.mode, c.risk, got, c.want)
		}
	}
}
