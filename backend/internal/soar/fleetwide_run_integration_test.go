package soar_test

// FleetWide — the CORE invariant, driven through the REAL run path (svc.Run → runFor), not a re-implemented
// expression. Owner decision Option 1: a fleet-wide action (blocks a hash across EVERY endpoint) must NEVER
// auto-run under ANY authority mode — including the most permissive — yet must stay approvable-and-runnable by a
// manager (reachable, not the business_critical phantom).
//
// WHY THE PER-ACTION POLICY (not SetAuthority): Round-4 L3 already forbids the '*' catch-all from being permissive
// (pre_authorized/contractual_auto must be scoped to a specific action_type, platform_admin only). So the realistic
// worst case — and the one FleetWide must survive — is an admin DELIBERATELY granting contractual_auto to the
// fleet-wide action itself. These tests set exactly that, then assert the gate still refuses.
//
// MUTATION CHECK (verified): drop `!act.FleetWide` from service.go's autoEligible →
// TestFleetWide_NeverAutoRuns_EvenWhenAdminGrantsContractualAuto goes RED. An earlier draft asserted on a local
// copy of the expression and stayed GREEN under that mutation — a false green. This drives the shipped path.

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func TestFleetWide_NeverAutoRuns_EvenWhenAdminGrantsContractualAuto(t *testing.T) {
	svc, db, tid, ctx := authoringSetup(t)
	ts := tenant.NewService(tenant.NewRepository(db))
	// An admin explicitly grants autonomous execution to the fleet-wide action itself. This is the worst case.
	if _, err := ts.SetAuthorityPolicy(ctx, principal(tid, auth.RolePlatformAdmin), tid,
		tenant.AuthorityInput{ActionType: "cs_block_hash", Mode: "contractual_auto"}); err != nil {
		t.Fatalf("grant contractual_auto to cs_block_hash: %v", err)
	}
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name: "fleetwide-block-run",
		// cs_block_hash is seeded high + fleet_wide=true (mig 0134). RequiresApproval=false on purpose:
		// the ONLY thing that can stop an auto-fire here is the FleetWide gate.
		Steps: []soar.Step{stepIn("block the hash", "cs_block_hash", soar.RiskHigh, false)},
	})
	if err != nil {
		t.Fatalf("create playbook: %v", err)
	}
	run, err := svc.Run(ctx, mgr(tid), pb.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != soar.RunPendingApproval {
		t.Fatalf("FLEET-WIDE AUTO-FIRE: cs_block_hash auto-ran even though it is fleet_wide, after an admin granted "+
			"contractual_auto (run status=%q). A permissive mode must NEVER license a fleet-wide effect — this would "+
			"block a hash across EVERY endpoint in the tenant with no human in the loop", run.Status)
	}
	if len(run.Steps) != 1 || run.Steps[0].Status != soar.StatusAwaitingApproval {
		t.Fatalf("fleet-wide step must be awaiting_approval (reachable + manager-approvable), got %+v", run.Steps)
	}
}

// TestFleetWide_SingleTargetStillAutoRuns — the control. SAME risk (high), SAME grant, but single-target
// (fleet_wide=false) MUST still auto-run. Without this, a FleetWide gate that accidentally blocked ALL High
// containment would look "safe" while having silently broken automated response — the guard must discriminate on
// BREADTH, not on risk.
func TestFleetWide_SingleTargetStillAutoRuns(t *testing.T) {
	svc, db, tid, ctx := authoringSetup(t)
	ts := tenant.NewService(tenant.NewRepository(db))
	if _, err := ts.SetAuthorityPolicy(ctx, principal(tid, auth.RolePlatformAdmin), tid,
		tenant.AuthorityInput{ActionType: "cs_isolate_host", Mode: "contractual_auto"}); err != nil {
		t.Fatalf("grant contractual_auto to cs_isolate_host: %v", err)
	}
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name:  "single-target-run",
		Steps: []soar.Step{stepIn("isolate the host", "cs_isolate_host", soar.RiskHigh, false)}, // high, fleet_wide=false
	})
	if err != nil {
		t.Fatalf("create playbook: %v", err)
	}
	run, err := svc.Run(ctx, mgr(tid), pb.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(run.Steps) != 1 {
		t.Fatalf("want 1 step, got %+v", run.Steps)
	}
	if run.Steps[0].Status == soar.StatusAwaitingApproval {
		t.Fatalf("regression: a single-target High action must STILL auto-run once an admin grants contractual_auto — "+
			"the FleetWide gate must gate on BREADTH, not disable High containment generally. status=%q note=%q",
			run.Steps[0].Status, run.Steps[0].Note)
	}
}
