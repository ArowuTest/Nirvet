package fleet

// The fleet DESTRUCTIVE composition (#3/#5) at the fleet boundary: FireContainment/ApproveContainment must
// resolve the TARGET tenant FROM THE ALERT and refuse any principal without fleet scope BEFORE handing off to
// the SOAR runner. This uses a fake ContainmentRunner so the fleet gate is tested in isolation from SOAR
// internals (the per-target authority itself is proven against the real supervisor in the soar package).
//
// Invariants proved here:
//   - target-from-resource: the runner is invoked with the ALERT's tenant, even when the operator's own
//     principal carries a different tenant, and it can't be redirected by a forged id;
//   - NO destructive path for a non-provider: a customer_admin (even of the alert's own tenant) is refused
//     and the runner is NEVER invoked — a pure oversight/customer principal cannot fire a containment;
//   - fire-time resolution: the target is resolved at the moment of firing, not supplied by the caller.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// fakeContainment records how the fleet layer hands off to SOAR, so a test can assert the (operator, target)
// pair the runner is invoked with — or that it is never invoked at all.
type fakeContainment struct {
	calls    int
	operator auth.Principal
	target   uuid.UUID
	playbook uuid.UUID
}

func (f *fakeContainment) RunForTarget(_ context.Context, operator auth.Principal, targetTenant, playbookID uuid.UUID, _ *uuid.UUID) (uuid.UUID, string, error) {
	f.calls++
	f.operator, f.target, f.playbook = operator, targetTenant, playbookID
	return uuid.New(), "running", nil
}

func (f *fakeContainment) ApproveForTarget(_ context.Context, operator auth.Principal, targetTenant, runID uuid.UUID) (uuid.UUID, string, error) {
	f.calls++
	f.operator, f.target = operator, targetTenant
	return runID, "completed", nil
}

func TestFleetFireContainment_TargetFromResource_NoPathForOversight(t *testing.T) {
	db := fleetDB(t)
	fake := &fakeContainment{}
	svc := NewService(db).WithContainment(fake)
	ctx := context.Background()

	tA := mkTenant(t, db)
	alertID := mkAlertID(t, db, tA)
	playbookID := uuid.New()

	// (1) A provider operator whose OWN principal carries a different tenant fires on tA's alert → the runner
	// is invoked with the ALERT's tenant (tA) and the operator's identity. Target comes from the resource.
	op := auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RoleSOCManager, Email: "op@venture"}
	if _, _, err := svc.FireContainment(ctx, op, alertID, playbookID, nil); err != nil {
		t.Fatalf("provider fire: %v", err)
	}
	if fake.calls != 1 || fake.target != tA {
		t.Fatalf("runner must be invoked once with the ALERT's tenant (tA=%s), got calls=%d target=%s", tA, fake.calls, fake.target)
	}
	if fake.operator.UserID != op.UserID || fake.playbook != playbookID {
		t.Fatalf("runner must receive the operator identity + playbook, got op=%s pb=%s", fake.operator.UserID, fake.playbook)
	}

	// (2) A non-provider (customer_admin OF tA, which OWNS the alert) has NO destructive path: refused, and the
	// runner is NEVER invoked — the pure oversight/customer principal cannot fire a containment.
	cust := auth.Principal{UserID: uuid.New(), TenantID: tA, Role: auth.RoleCustomerAdmin, Email: "c@mda"}
	if _, _, err := svc.FireContainment(ctx, cust, alertID, playbookID, nil); err == nil {
		t.Fatal("a non-provider MUST have no destructive path (expected refusal)")
	}
	if fake.calls != 1 {
		t.Fatalf("the runner MUST NOT be invoked for a non-provider, calls=%d", fake.calls)
	}

	// (3) A forged / nonexistent alert id → refused, runner not invoked (no redirect, no leak).
	if _, _, err := svc.FireContainment(ctx, op, uuid.New(), playbookID, nil); err == nil {
		t.Fatal("a forged/nonexistent alert id MUST be refused")
	}
	if fake.calls != 1 {
		t.Fatalf("a forged id MUST NOT invoke the runner, calls=%d", fake.calls)
	}

	// (4) ApproveContainment enforces the same fleet gate: a non-provider is refused, the runner not invoked.
	if _, _, err := svc.ApproveContainment(ctx, cust, alertID, uuid.New()); err == nil {
		t.Fatal("a non-provider MUST NOT be able to approve a cross-tenant containment")
	}
	if fake.calls != 1 {
		t.Fatalf("approve by a non-provider MUST NOT invoke the runner, calls=%d", fake.calls)
	}
}

// TestFleetContainment_NotConfiguredRefuses: with no runner wired, a fleet fire by an authorized operator
// refuses (fail-safe) rather than silently no-op'ing.
func TestFleetContainment_NotConfiguredRefuses(t *testing.T) {
	db := fleetDB(t)
	svc := NewService(db) // no WithContainment
	ctx := context.Background()
	tA := mkTenant(t, db)
	alertID := mkAlertID(t, db, tA)
	op := auth.Principal{UserID: uuid.New(), TenantID: mkTenant(t, db), Role: auth.RoleSOCManager}
	if _, _, err := svc.FireContainment(ctx, op, alertID, uuid.New(), nil); err == nil {
		t.Fatal("fleet fire with no containment runner wired MUST refuse (fail-safe), not no-op")
	}
}
