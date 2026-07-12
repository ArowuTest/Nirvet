package soar

// §6.11 #188 HEAVY-2 (sub-commit 2/3) — customer-approval gate landing round (DB-gated). The reviewer's
// discriminating invariants: default preserves behavior; both_required needs BOTH distinct principals (customer
// alone can't fire); the dual-role guard (one person can't fill both slots); four-eyes on the internal principal;
// nil-requester rejected; customer_approver executes as a synthetic customer principal (no platform rank).

import (
	"context"
	"errors"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// caStatusIs reports whether err is an httpx.APIError with the given HTTP status.
func caStatusIs(err error, code int) bool {
	var ae *httpx.APIError
	return err != nil && errors.As(err, &ae) && ae.Status == code
}

func caDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func caTenant(t *testing.T, db *database.DB) (auth.Principal, uuid.UUID) {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "ca-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return auth.Principal{TenantID: tn.ID, UserID: uuid.New(), Email: "admin@ca", Role: auth.RoleSOCManager}, tn.ID
}

// Default policy is platform_analyst (no behavior change); a set customer_approver resolves; invalid rejected.
func TestCA_PolicyDefaultAndSet(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()

	if pol := svc.resolveCustomerPolicy(ctx, tid); pol.Authority != AuthorityPlatformAnalyst {
		t.Fatalf("fresh tenant must default to platform_analyst; got %q", pol.Authority)
	}
	if _, err := svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityCustomerApprover, LinkTTLSeconds: 7200, CustomerApproverRef: "cust@x"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if pol := svc.resolveCustomerPolicy(ctx, tid); pol.Authority != AuthorityCustomerApprover {
		t.Fatalf("policy should resolve to customer_approver; got %q", pol.Authority)
	}
	if _, err := svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: "bogus", LinkTTLSeconds: 7200}); err == nil {
		t.Fatal("invalid authority must be rejected")
	}
}

// both_required: needs BOTH a distinct internal AND customer approval — customer (or internal) alone is not ready.
func TestCA_GateBothRequiredNeedsBothDistinct(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()
	if _, err := svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityBothRequired, LinkTTLSeconds: 7200}); err != nil {
		t.Fatalf("set: %v", err)
	}
	policy := svc.resolveCustomerPolicy(ctx, tid)
	req := uuid.New()
	run := &PlaybookRun{ID: uuid.New(), RequestedBy: &req}

	// Internal only → not ready.
	iid := uuid.New()
	mustRecord(t, svc, tid, run.ID, approvalInternal, &iid, "analyst@x", string(auth.RoleSOCManager))
	if ready, _, _, err := svc.evaluateGate(ctx, tid, run, policy); err != nil || ready {
		t.Fatalf("both_required with internal only must NOT be ready; ready=%v err=%v", ready, err)
	}
	// + distinct customer → ready, executes as the internal approver, rank enforced (skipInternalRank=false).
	mustRecord(t, svc, tid, run.ID, approvalCustomer, nil, "cust@x", "")
	ready, execP, ea, err := svc.evaluateGate(ctx, tid, run, policy)
	if err != nil || !ready {
		t.Fatalf("both_required with both distinct must be ready; ready=%v err=%v", ready, err)
	}
	if execP.UserID != iid || ea.skipInternalRank {
		t.Fatalf("both_required must execute as the internal approver with rank enforced; execP=%v skip=%v", execP.UserID, ea.skipInternalRank)
	}
}

// Dual-role guard: the same person (same ref) cannot fill both the internal and the customer slot.
func TestCA_GateDualRoleRejected(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()
	_, _ = svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityBothRequired, LinkTTLSeconds: 7200})
	policy := svc.resolveCustomerPolicy(ctx, tid)
	req := uuid.New()
	run := &PlaybookRun{ID: uuid.New(), RequestedBy: &req}

	iid := uuid.New()
	mustRecord(t, svc, tid, run.ID, approvalInternal, &iid, "same@x", string(auth.RoleSOCManager))
	mustRecord(t, svc, tid, run.ID, approvalCustomer, nil, "same@x", "")
	_, _, _, err := svc.evaluateGate(ctx, tid, run, policy)
	if !caStatusIs(err, 403) {
		t.Fatalf("the same principal must not fill both slots (expected 403); got %v", err)
	}
}

// Four-eyes on the internal principal: the requester cannot be the internal approver.
func TestCA_GateFourEyesInternal(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()
	_, _ = svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityBothRequired, LinkTTLSeconds: 7200})
	policy := svc.resolveCustomerPolicy(ctx, tid)
	req := uuid.New()
	run := &PlaybookRun{ID: uuid.New(), RequestedBy: &req}

	mustRecord(t, svc, tid, run.ID, approvalInternal, &req, "analyst@x", string(auth.RoleSOCManager)) // internal == requester
	mustRecord(t, svc, tid, run.ID, approvalCustomer, nil, "cust@x", "")
	_, _, _, err := svc.evaluateGate(ctx, tid, run, policy)
	if !caStatusIs(err, 403) {
		t.Fatalf("requester must not be the internal approver (expected 403); got %v", err)
	}
}

// customer_approver: a customer approval alone is ready, executing as a synthetic customer principal (no rank);
// an internal approval alone is not ready.
func TestCA_GateCustomerApproverMode(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()
	_, _ = svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityCustomerApprover, LinkTTLSeconds: 7200})
	policy := svc.resolveCustomerPolicy(ctx, tid)
	req := uuid.New()

	run1 := &PlaybookRun{ID: uuid.New(), RequestedBy: &req}
	mustRecord(t, svc, tid, run1.ID, approvalCustomer, nil, "cust@x", "")
	ready, execP, ea, err := svc.evaluateGate(ctx, tid, run1, policy)
	if err != nil || !ready || execP.UserID != uuid.Nil || !ea.skipInternalRank {
		t.Fatalf("customer_approver with a customer approval must be ready as a synthetic principal; ready=%v execP=%v skip=%v err=%v", ready, execP.UserID, ea.skipInternalRank, err)
	}
	run2 := &PlaybookRun{ID: uuid.New(), RequestedBy: &req}
	iid := uuid.New()
	mustRecord(t, svc, tid, run2.ID, approvalInternal, &iid, "analyst@x", string(auth.RoleSOCManager))
	if ready, _, _, _ := svc.evaluateGate(ctx, tid, run2, policy); ready {
		t.Fatal("customer_approver with internal only must NOT be ready (needs the customer)")
	}
}

// nil-requester is rejected (no four-eyes possible → fail-closed).
func TestCA_GateNilRequesterRejected(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()
	_, _ = svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityBothRequired, LinkTTLSeconds: 7200})
	policy := svc.resolveCustomerPolicy(ctx, tid)
	run := &PlaybookRun{ID: uuid.New(), RequestedBy: nil}
	if _, _, _, err := svc.evaluateGate(ctx, tid, run, policy); !caStatusIs(err, 403) {
		t.Fatalf("a nil-requester run must be rejected (expected 403); got %v", err)
	}
}

// ApproveViaLink: platform_analyst tenant rejects a customer link; both_required customer-alone leaves the run
// pending (never fires); the single-use link is consumed either way.
func TestCA_ApproveViaLinkGating(t *testing.T) {
	db := caDB(t)
	svc := NewService(NewRepository(db))
	p, tid := caTenant(t, db)
	ctx := context.Background()

	// platform_analyst (default) → a customer link is refused.
	run1 := seedPendingRun(t, db, tid, ptr(uuid.New()))
	tok1, err := svc.IssueApprovalLink(ctx, p, run1)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.ApproveViaLink(ctx, tok1); !caStatusIs(err, 403) {
		t.Fatalf("platform_analyst tenant must refuse customer approval (expected 403); got %v", err)
	}

	// both_required → a customer approval alone records but does NOT execute (run stays pending).
	_, _ = svc.SetCustomerPolicy(ctx, p, CustomerApprovalPolicy{Authority: AuthorityBothRequired, LinkTTLSeconds: 7200, CustomerApproverRef: "cust@x"})
	run2 := seedPendingRun(t, db, tid, ptr(uuid.New()))
	tok2, err := svc.IssueApprovalLink(ctx, p, run2)
	if err != nil {
		t.Fatalf("issue2: %v", err)
	}
	got, err := svc.ApproveViaLink(ctx, tok2)
	if err != nil {
		t.Fatalf("approve-via-link: %v", err)
	}
	if got.Status != RunPendingApproval {
		t.Fatalf("both_required with customer alone must stay pending (never fire); got %s", got.Status)
	}
	// The link is single-use: a replay is rejected.
	if _, err := svc.ApproveViaLink(ctx, tok2); err == nil {
		t.Fatal("the approval link must be single-use (replay rejected)")
	}
}

// helpers
func mustRecord(t *testing.T, svc *Service, tid, runID uuid.UUID, kind string, pid *uuid.UUID, ref, role string) {
	t.Helper()
	if err := svc.recordApproval(context.Background(), tid, runID, kind, pid, ref, role); err != nil {
		t.Fatalf("record %s: %v", kind, err)
	}
}

func ptr(u uuid.UUID) *uuid.UUID { return &u }

func seedPendingRun(t *testing.T, db *database.DB, tid uuid.UUID, requester *uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO playbook_runs (id, tenant_id, playbook_id, status, steps_result, requested_by)
			 VALUES ($1,$2,$3,'pending_approval','[]',$4)`, id, tid, uuid.New(), requester)
		return e
	}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	return id
}
