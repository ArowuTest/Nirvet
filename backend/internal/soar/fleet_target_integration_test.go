package soar_test

// §6.11 + fleet cross-tenant containment (#3/#5) — the highest-consequence surface: a fleet OPERATOR fires a
// destructive containment on ANOTHER tenant's resource. These tests prove the reviewer's per-target-authority
// invariant against a migrated Postgres with the REAL two-phase supervisor:
//
//   - Authority resolves in the TARGET tenant's context, NOT the operator's: a target whose destructive gate
//     is OFF withholds even when the OPERATOR's own tenant has it ON (and vice-versa) — the operator "acts
//     across the fleet within each tenant's own rules", never with a global capability.
//   - The fired effect + audit land DURABLY in the TARGET tenant (through the supervisor), not the operator's.
//   - Four-eyes bites across tenants: the operator who fired a pending run may not approve it, and the approver
//     floor is measured against the TARGET tenant's policy.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fleetFixture stands up the full RunForTarget path: a target tenant with a seeded containment playbook +
// action catalog + authority policy, a SEPARATE operator tenant, the real supervisor with a call-counting
// defender/isolate actioner, and the tenant authorizer. mode is the target's authority for "isolate".
type fleetFixture struct {
	db       *database.DB
	svc      *soar.Service
	repo     *soar.Repository
	target   uuid.UUID
	opTenant uuid.UUID
	pbID     uuid.UUID
	cc       *callCounter
}

func newFleetFixture(t *testing.T, mode string) *fleetFixture {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()

	repo := soar.NewRepository(db)
	t.Cleanup(func() { _ = repo.SetPlatformFlags(ctx, soar.PlatformFlags{}) })
	tenSvc := tenant.NewService(tenant.NewRepository(db))
	target, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "tgt-" + uuid.NewString()})
	opTenant, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "op-" + uuid.NewString()})

	cc := &callCounter{}
	reg := soar.NewActionerRegistry().Register(cc.actioner("defender", "isolate", true))
	sup := soar.NewSupervisor(repo, reg, mockCreds{}, nil)
	svc := soar.NewService(repo).WithSupervisor(sup).WithAuthorizer(tenSvc)

	// Seed a containment playbook in the TARGET tenant (the operator fires the target's OWN playbook).
	pbID := uuid.New()
	if err := db.WithTenant(ctx, target.ID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO playbooks (id, tenant_id, name, description, trigger_category, steps, enabled)
			 VALUES ($1,$2,'fleet-contain','', 'malware', $3::jsonb, true)`,
			pbID, target.ID, `[{"name":"isolate","connector_key":"defender","action":"isolate","target":"host:h1"}]`)
		return e
	}); err != nil {
		t.Fatalf("seed target playbook: %v", err)
	}

	// A platform_admin seeds the TARGET's action catalog (isolate = high, connector) + authority for isolate.
	admin := auth.Principal{UserID: uuid.New(), Email: "seed@op", TenantID: target.ID, Role: auth.RolePlatformAdmin}
	enabled := true
	if _, err := svc.SetActionCatalog(ctx, admin, target.ID, soar.ActionCatalogInput{
		ActionKey: "isolate", Title: "Isolate host", RiskClass: soar.RiskHigh, Executor: soar.ExecutorConnector,
		ConnectorKey: "defender", Enabled: &enabled,
	}); err != nil {
		t.Fatalf("seed target action catalog: %v", err)
	}
	if _, err := tenSvc.SetAuthorityPolicy(ctx, admin, target.ID, tenant.AuthorityInput{ActionType: "isolate", Mode: mode}); err != nil {
		t.Fatalf("seed target authority (%s): %v", mode, err)
	}

	return &fleetFixture{db: db, svc: svc, repo: repo, target: target.ID, opTenant: opTenant.ID, pbID: pbID, cc: cc}
}

// TestRunForTarget_AuthorityResolvesInTarget is the crux: the destructive gate that governs a fleet fire is
// the TARGET tenant's, never the operator's. isolate is emergency-authorized (auto-eligible) so the fire
// reaches the supervisor gate directly.
func TestRunForTarget_AuthorityResolvesInTarget(t *testing.T) {
	fx := newFleetFixture(t, "emergency")
	ctx := context.Background()

	// The operator's OWN tenant has the destructive gate ON — this must be irrelevant to a fire on the target.
	_ = fx.repo.SetSoarSettings(ctx, fx.opTenant, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	// The TARGET tenant has the destructive gate OFF.
	_ = fx.repo.SetSoarSettings(ctx, fx.target, soar.SoarSettings{DestructiveEnabled: false, MaxClass3PerHour: 5})

	operator := auth.Principal{UserID: uuid.New(), Email: "op@venture", TenantID: fx.opTenant, Role: auth.RoleSOCManager}
	runID, status, err := fx.svc.RunForTarget(ctx, operator, fx.target, fx.pbID, nil)
	if err != nil {
		t.Fatalf("RunForTarget (target gate off): %v", err)
	}
	// The TARGET governs: the action is WITHHELD and the connector is NEVER called — even though the
	// operator's own tenant has destructive_enabled=true. Authority is read from the target, not the operator.
	if fx.cc.n != 0 {
		t.Fatalf("target destructive_enabled=false MUST withhold — no real effect — but the actioner was called %d times (operator's own gate must be irrelevant)", fx.cc.n)
	}
	// The run landed in the TARGET tenant, not the operator's.
	if _, err := fx.svc.GetRun(ctx, fx.target, runID); err != nil {
		t.Fatalf("run must exist in the TARGET tenant: %v", err)
	}
	if _, err := fx.svc.GetRun(ctx, fx.opTenant, runID); err == nil {
		t.Fatal("run must NOT exist in the operator's own tenant (it belongs to the target)")
	}
	run, _ := fx.svc.GetRun(ctx, fx.target, runID)
	if run.Steps[0].Status != soar.StatusWithheld {
		t.Fatalf("step must be withheld by the target's gate, got %s (status=%s)", run.Steps[0].Status, status)
	}

	// Now turn the TARGET's gate ON and fire again: the action executes ONCE, and it landed in the target.
	_ = fx.repo.SetSoarSettings(ctx, fx.target, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	runID2, _, err := fx.svc.RunForTarget(ctx, operator, fx.target, fx.pbID, nil)
	if err != nil {
		t.Fatalf("RunForTarget (target gate on): %v", err)
	}
	if fx.cc.n != 1 {
		t.Fatalf("with the target's gate ON the containment fires exactly once, got %d", fx.cc.n)
	}
	run2, err := fx.svc.GetRun(ctx, fx.target, runID2)
	if err != nil || run2.Steps[0].Status != soar.StatusExecuted {
		t.Fatalf("fired action must land executed in the TARGET tenant, got %v / %s", err, run2.Steps[0].Status)
	}
	// The operator is the actor of the durable outcome audit (supervisor two-phase) in the TARGET tenant —
	// so the agency sees who fired the containment on its resource, and the record is durable (not best-effort).
	assertTargetAudit(t, fx.db, fx.target, "soar.action_outcome", operator.UserID)
}

// TestApproveForTarget_FourEyesAcrossTenants: with the target on APPROVAL authority, a fleet fire leaves the
// run pending in the TARGET; the operator who fired it may not approve it (four-eyes), a too-junior operator
// is refused (floor from the target's high-risk policy), and a distinct senior operator approves — the effect
// then fires once in the target.
func TestApproveForTarget_FourEyesAcrossTenants(t *testing.T) {
	fx := newFleetFixture(t, "approval")
	ctx := context.Background()
	_ = fx.repo.SetSoarSettings(ctx, fx.target, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})

	firer := auth.Principal{UserID: uuid.New(), Email: "firer@venture", TenantID: fx.opTenant, Role: auth.RoleSOCManager}
	runID, status, err := fx.svc.RunForTarget(ctx, firer, fx.target, fx.pbID, nil)
	if err != nil {
		t.Fatalf("RunForTarget (approval mode): %v", err)
	}
	if status != string(soar.RunPendingApproval) {
		t.Fatalf("a high-risk step under approval authority must be pending, got %s", status)
	}
	if fx.cc.n != 0 {
		t.Fatal("nothing fires before approval")
	}

	// Four-eyes across tenants: the operator who FIRED the run may not approve it.
	if _, _, err := fx.svc.ApproveForTarget(ctx, firer, fx.target, runID); err == nil {
		t.Fatal("four-eyes: the operator who fired the containment MUST NOT be able to approve it")
	}
	// Approver floor measured against the TARGET's high-risk policy: a too-junior operator is refused.
	junior := auth.Principal{UserID: uuid.New(), Email: "t1@venture", TenantID: fx.opTenant, Role: auth.RoleAnalystT1}
	if _, _, err := fx.svc.ApproveForTarget(ctx, junior, fx.target, runID); err == nil {
		t.Fatal("approver floor: a too-junior operator MUST NOT approve a high-risk containment")
	}
	if fx.cc.n != 0 {
		t.Fatal("no effect from refused approvals")
	}

	// A distinct, sufficiently-senior operator approves → the containment fires once, in the target.
	approver := auth.Principal{UserID: uuid.New(), Email: "mgr@venture", TenantID: fx.opTenant, Role: auth.RoleSOCManager}
	if _, _, err := fx.svc.ApproveForTarget(ctx, approver, fx.target, runID); err != nil {
		t.Fatalf("a distinct senior operator must be able to approve: %v", err)
	}
	if fx.cc.n != 1 {
		t.Fatalf("approved containment fires exactly once, got %d", fx.cc.n)
	}
	assertTargetAudit(t, fx.db, fx.target, "soar.run_approve", approver.UserID)
}

// TestRejectForTarget_CancelsPendingInTarget: an operator can cancel a pending cross-tenant containment
// (fail-safe — nothing fires), and the run is rejected in the TARGET tenant.
func TestRejectForTarget_CancelsPendingInTarget(t *testing.T) {
	fx := newFleetFixture(t, "approval")
	ctx := context.Background()
	_ = fx.repo.SetSoarSettings(ctx, fx.target, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})

	firer := auth.Principal{UserID: uuid.New(), Email: "firer@venture", TenantID: fx.opTenant, Role: auth.RoleSOCManager}
	runID, _, err := fx.svc.RunForTarget(ctx, firer, fx.target, fx.pbID, nil)
	if err != nil {
		t.Fatalf("RunForTarget: %v", err)
	}

	// Any authorized operator may cancel the pending run (no four-eyes on the fail-safe direction).
	other := auth.Principal{UserID: uuid.New(), Email: "other@venture", TenantID: fx.opTenant, Role: auth.RoleSOCManager}
	_, status, err := fx.svc.RejectForTarget(ctx, other, fx.target, runID)
	if err != nil {
		t.Fatalf("RejectForTarget: %v", err)
	}
	if status != string(soar.RunRejected) {
		t.Fatalf("rejected run status must be rejected, got %s", status)
	}
	if fx.cc.n != 0 {
		t.Fatalf("reject is fail-safe — nothing fires, got %d actioner calls", fx.cc.n)
	}
	run, err := fx.svc.GetRun(ctx, fx.target, runID)
	if err != nil || run.Status != soar.RunRejected {
		t.Fatalf("run must be rejected in the TARGET tenant, got %v / %s", err, run.Status)
	}
}

// assertTargetAudit confirms an audit row for the given action + actor exists in the TARGET tenant.
func assertTargetAudit(t *testing.T, db *database.DB, target uuid.UUID, action string, actor uuid.UUID) {
	t.Helper()
	var n int
	if err := db.WithTenant(context.Background(), target, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1 AND actor_id=$2`, action, actor).Scan(&n)
	}); err != nil {
		t.Fatalf("read target audit: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected a %q audit row in the TARGET tenant with the operator's identity", action)
	}
}
