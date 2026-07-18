package soar_test

// FleetWide × Palo Alto network block — the repointed `block_ip` row (mig 0135: connector_key defender→palo-alto)
// must STILL be fleet_wide and therefore never auto-run. This is premise §7.4 of the Palo Alto gate driven through
// the REAL run path (svc.Run → runFor), not a re-implemented expression: a perimeter block has tenant-wide blast
// radius, so an admin granting contractual_auto to block_ip itself must NOT license an auto-fire — the gate refuses
// (before ever reaching the actioner) and the step lands awaiting_approval (reachable, manager-approvable).
//
// MUTATION CHECK (verify with `go test -run TestFleetWide_BlockIP_NeverAutoRuns -v`, confirm it EXECUTES and PASSES,
// then that it goes RED when the guard is removed): drop `!act.FleetWide` from service.go's autoEligible → this test
// goes RED. If the repoint in mig 0135 had dropped fleet_wide on block_ip, this test would also go RED. Both are the
// real invariant, not a tautology.

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func TestFleetWide_BlockIP_NeverAutoRuns(t *testing.T) {
	svc, db, tid, ctx := authoringSetup(t)
	ts := tenant.NewService(tenant.NewRepository(db))
	// Worst case: an admin explicitly grants autonomous execution to the fleet-wide network block itself.
	if _, err := ts.SetAuthorityPolicy(ctx, principal(tid, auth.RolePlatformAdmin), tid,
		tenant.AuthorityInput{ActionType: "block_ip", Mode: "contractual_auto"}); err != nil {
		t.Fatalf("grant contractual_auto to block_ip: %v", err)
	}
	pb, err := svc.CreatePlaybook(ctx, mgr(tid), tid, soar.PlaybookInput{
		Name: "fleetwide-block-ip-run",
		// block_ip is seeded high + fleet_wide=true (0134) and repointed to palo-alto (0135). RequiresApproval=false
		// on purpose: the ONLY thing that can stop an auto-fire here is the FleetWide gate.
		Steps: []soar.Step{stepIn("block the source IP", "block_ip", soar.RiskHigh, false)},
	})
	if err != nil {
		t.Fatalf("create playbook: %v", err)
	}
	run, err := svc.Run(ctx, mgr(tid), pb.ID, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != soar.RunPendingApproval {
		t.Fatalf("FLEET-WIDE AUTO-FIRE: block_ip auto-ran even though it is fleet_wide, after an admin granted "+
			"contractual_auto (run status=%q). A perimeter block has tenant-wide blast radius and must never fire "+
			"without a human in the loop — and the 0135 repoint must not have dropped fleet_wide", run.Status)
	}
	if len(run.Steps) != 1 || run.Steps[0].Status != soar.StatusAwaitingApproval {
		t.Fatalf("fleet-wide block_ip step must be awaiting_approval (reachable + manager-approvable), got %+v", run.Steps)
	}
}
