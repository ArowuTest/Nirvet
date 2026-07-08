package soar

import (
	"testing"

	"github.com/google/uuid"
)

// TestSeparationOfDuties locks the four-eyes control on approvals: the user who
// requested a SOAR run may not approve it, but a different approver can, and a
// system-initiated run (no requester) is approvable by any authorised approver.
func TestSeparationOfDuties(t *testing.T) {
	requester := uuid.New()
	other := uuid.New()

	own := &PlaybookRun{RequestedBy: &requester}
	if err := canApprove(own, requester); err == nil {
		t.Fatal("requester must NOT be allowed to approve their own run (self-approval)")
	}
	if err := canApprove(own, other); err != nil {
		t.Fatalf("a different approver must be allowed: %v", err)
	}

	system := &PlaybookRun{} // no RequestedBy (correlation/auto-initiated)
	if err := canApprove(system, other); err != nil {
		t.Fatalf("system-initiated run should be approvable by any approver: %v", err)
	}
}

// TestAuthorityMatrix locks the authority-to-act policy (doc 03 §6 / doc 04 §9.5):
// which risk classes may auto-execute (without approval) under each tenant mode.
func TestAuthorityMatrix(t *testing.T) {
	cases := []struct {
		mode AuthorityMode
		risk RiskClass
		want bool
	}{
		{AuthorityObserve, RiskLow, false}, // observe: nothing auto-runs
		{AuthorityObserve, RiskCritical, false},
		{AuthorityApproval, RiskLow, true}, // approval: only low auto-runs
		{AuthorityApproval, RiskMedium, false},
		{AuthorityApproval, RiskHigh, false},
		{AuthorityPreAuth, RiskLow, true}, // pre-auth: low + medium
		{AuthorityPreAuth, RiskMedium, true},
		{AuthorityPreAuth, RiskHigh, false},
		{AuthorityEmergency, RiskHigh, true},      // emergency: up to high
		{AuthorityEmergency, RiskCritical, false}, // NEVER auto-run critical
		{"bogus", RiskLow, false},                 // unknown mode denies
	}
	for _, c := range cases {
		if got := Allowed(c.mode, c.risk); got != c.want {
			t.Errorf("Allowed(%s, %s) = %v, want %v", c.mode, c.risk, got, c.want)
		}
	}
}
