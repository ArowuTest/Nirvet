package soar

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// TestAuthorityMatrix locks the authority-to-act policy against the SRS §9.5 five-class scale:
// which risk classes may auto-execute (without approval) under each tenant authority mode.
func TestAuthorityMatrix(t *testing.T) {
	cases := []struct {
		mode AuthorityMode
		risk RiskClass
		want bool
	}{
		{AuthorityObserve, RiskInformational, false}, // observe: nothing auto-runs, even informational
		{AuthorityObserve, RiskLow, false},
		{AuthorityObserve, RiskBusinessCritical, false},
		{AuthorityApproval, RiskInformational, true}, // approval: informational + low auto-run
		{AuthorityApproval, RiskLow, true},
		{AuthorityApproval, RiskMedium, false},
		{AuthorityApproval, RiskHigh, false},
		{AuthorityPreAuth, RiskLow, true}, // pre-auth: informational + low + medium
		{AuthorityPreAuth, RiskMedium, true},
		{AuthorityPreAuth, RiskHigh, false},
		{AuthorityContractualAuto, RiskHigh, true}, // contractual_auto: up to high
		{"bogus", RiskLow, false},                  // unknown mode denies
	}
	for _, c := range cases {
		if got := Allowed(c.mode, c.risk); got != c.want {
			t.Errorf("Allowed(%s, %s) = %v, want %v", c.mode, c.risk, got, c.want)
		}
	}
}

// TestBusinessCriticalNeverAutonomous locks the §9.5 Class-4 guarantee: a business_critical action
// NEVER auto-executes under ANY authority mode — including emergency.
func TestBusinessCriticalNeverAutonomous(t *testing.T) {
	for _, mode := range []AuthorityMode{AuthorityObserve, AuthorityApproval, AuthorityPreAuth, AuthorityContractualAuto} {
		if Allowed(mode, RiskBusinessCritical) {
			t.Fatalf("business_critical must never auto-run, but Allowed(%s, business_critical)=true", mode)
		}
	}
}

// TestRiskRankMonotonic locks the ordering the M1 override-clamp relies on: informational < low <
// medium < high < business_critical, and an unknown class ranks as max (fail-closed). So
// max(seeded, override) can only RAISE an action's risk, never lower it.
func TestRiskRankMonotonic(t *testing.T) {
	order := []RiskClass{RiskInformational, RiskLow, RiskMedium, RiskHigh, RiskBusinessCritical}
	for i := 1; i < len(order); i++ {
		if riskRank(order[i]) <= riskRank(order[i-1]) {
			t.Fatalf("riskRank must increase: %s(%d) !> %s(%d)", order[i], riskRank(order[i]), order[i-1], riskRank(order[i-1]))
		}
	}
	if riskRank("nonsense") != riskRank(RiskBusinessCritical) {
		t.Fatalf("unknown class must rank as max (fail-closed)")
	}
}

// fakeExecutor records calls and returns a preset outcome/error for dispatch tests.
type fakeExecutor struct {
	called bool
	out    Outcome
	err    error
}

func (f *fakeExecutor) Execute(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ string, _ map[string]any) (Outcome, error) {
	f.called = true
	return f.out, f.err
}

// TestExecutorDispatch locks the executor registry's routing: a registered executor runs (executed
// vs simulated per its Outcome; failed on error), a manual action awaits the customer, and an
// unregistered action falls back to a truthful simulation naming the connector.
func TestExecutorDispatch(t *testing.T) {
	tid := uuid.New()
	ctx := context.Background()

	// Registered + executed (tx is nil — these executors don't touch the DB).
	fe := &fakeExecutor{out: Outcome{Executed: true, Detail: "did the thing"}}
	reg := NewExecutors().Register("notify_analyst", fe)
	st, note := reg.dispatch(ctx, nil, tid, ActionCatalog{ActionKey: "notify_analyst", Executor: ExecutorInternal}, nil)
	if st != StatusExecuted || !fe.called || note != "did the thing" {
		t.Fatalf("registered executor should run: status=%s called=%v note=%q", st, fe.called, note)
	}

	// Registered but errored → failed (SOAR-009, no panic).
	reg2 := NewExecutors().Register("notify_analyst", &fakeExecutor{err: errBoom})
	if st, _ := reg2.dispatch(ctx, nil, tid, ActionCatalog{ActionKey: "notify_analyst", Executor: ExecutorInternal}, nil); st != StatusFailed {
		t.Fatalf("executor error should yield failed, got %s", st)
	}

	// Registered but PANICKING → recovered as failed (Round-4 M4, no run-aborting panic).
	reg3 := NewExecutors().Register("notify_analyst", &panicExecutor{})
	if st, _ := reg3.dispatch(ctx, nil, tid, ActionCatalog{ActionKey: "notify_analyst", Executor: ExecutorInternal}, nil); st != StatusFailed {
		t.Fatalf("panicking executor should be recovered as failed, got %s", st)
	}

	// Manual action → awaiting customer.
	if st, _ := NewExecutors().dispatch(ctx, nil, tid, ActionCatalog{ActionKey: "request_customer_action", Executor: ExecutorManual}, nil); st != StatusAwaitingCustomer {
		t.Fatalf("manual action should await customer, got %s", st)
	}

	// Unregistered connector action → truthful simulation.
	st, note = NewExecutors().dispatch(ctx, nil, tid, ActionCatalog{ActionKey: "isolate_endpoint", Executor: ExecutorConnector, ConnectorKey: "defender"}, nil)
	if st != StatusSimulated || note == "" {
		t.Fatalf("unregistered action should simulate, got status=%s note=%q", st, note)
	}
}

// TestApproverFloor locks the Round-4 H2 approver-role floor: seniority required scales with §9.5
// risk class and is raised (never lowered) by a configured approver_role.
func TestApproverFloor(t *testing.T) {
	// A high-risk step requires soc_manager; analyst_t3 is insufficient, soc_manager suffices.
	highFloor := requiredApproverRank(RiskHigh, "")
	if auth.RoleRank(auth.RoleAnalystT3) >= highFloor {
		t.Fatal("analyst_t3 must NOT be able to approve a high-risk action")
	}
	if auth.RoleRank(auth.RoleSOCManager) < highFloor {
		t.Fatal("soc_manager must be able to approve a high-risk action")
	}
	// Medium needs analyst_t3; low/informational have no default floor.
	if requiredApproverRank(RiskMedium, "") != auth.RoleRank(auth.RoleAnalystT3) {
		t.Fatal("medium floor should be analyst_t3")
	}
	if requiredApproverRank(RiskLow, "") != 0 {
		t.Fatal("low should have no default floor")
	}
	// A configured approver_role can only RAISE the floor, never lower it.
	if requiredApproverRank(RiskLow, string(auth.RoleSOCManager)) != auth.RoleRank(auth.RoleSOCManager) {
		t.Fatal("configured approver_role must raise a low-risk floor to soc_manager")
	}
	if requiredApproverRank(RiskHigh, string(auth.RoleAnalystT1)) != highFloor {
		t.Fatal("a weaker configured approver_role must not lower the risk-scaled floor")
	}
}

// panicExecutor panics to exercise the M4 per-step recover().
type panicExecutor struct{}

func (panicExecutor) Execute(_ context.Context, _ pgx.Tx, _ uuid.UUID, _ string, _ map[string]any) (Outcome, error) {
	panic("boom in executor")
}

var errBoom = errTest("boom")

type errTest string

func (e errTest) Error() string { return string(e) }
