package reporting

// §6.13 #173 report-approval tests. The pure guard (canReviewReport) is DB-free; the workflow is DB-gated
// (RequireDSN → skip locally, run in CI). Load-bearing falsification probes: creator cannot self-approve,
// a junior cannot approve, a decided report cannot be re-decided (atomic guard), a pending_review report is
// NOT downloadable, a rejected report is terminally non-releasable, cross-tenant approve resolves to not-found.
//
// Review-required fixtures use the breach_report type (seeded review_required=true in 0141). The breach helpers
// (seedBreachIncident, repSvcBreach) live in breach_integration_test.go.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// managerActor is a soc_manager principal in the tenant (an eligible report approver).
func managerActor(tid uuid.UUID) auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: tid, Role: auth.RoleSOCManager, Email: "m@rep"}
}

// auditCount counts report_audit rows for an action in a tenant.
func auditCount(t *testing.T, db *database.DB, tid uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM report_audit WHERE tenant_id=$1 AND action=$2`, tid, action).Scan(&n)
	}); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	return n
}

// canReviewReport: a junior is refused; the creator is refused (four-eyes); a distinct senior is cleared.
func TestCanReviewReport(t *testing.T) {
	creator := uuid.New()
	manager := uuid.New()
	if err := canReviewReport(auth.RoleAnalystT1, creator, uuid.New()); err == nil {
		t.Fatal("a junior analyst must not be able to review a report")
	}
	if err := canReviewReport(auth.RoleSOCManager, creator, creator); err == nil {
		t.Fatal("the creator of a report must not be able to review it (four-eyes)")
	}
	if err := canReviewReport(auth.RoleSOCManager, creator, manager); err != nil {
		t.Fatalf("a distinct soc_manager must be able to review: %v", err)
	}
	if err := canReviewReport(auth.RolePlatformAdmin, creator, manager); err != nil {
		t.Fatalf("a platform_admin must be able to review: %v", err)
	}
}

// A review-required type (breach_report, seeded review_required=true) lands pending_review and is NOT downloadable
// until a distinct senior approves it. Headline workflow probe.
func TestReportApproval_ReviewGateReleasesOnApprove(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvcBreach(t, db)
	ctx := context.Background()

	creator := repActor(tid) // analyst_t1
	incID := seedBreachIncident(t, db, tid, "unauthorized access")
	rep, err := svc.GenerateBreachReport(ctx, creator, incID, FormatCSV)
	if err != nil {
		t.Fatalf("generate breach: %v", err)
	}
	if rep.ReviewStatus != "pending_review" {
		t.Fatalf("a review-required report must land pending_review, got %q", rep.ReviewStatus)
	}
	if _, _, err := svc.Download(ctx, creator, rep.ID); err == nil {
		t.Fatal("a pending_review report must NOT be downloadable before approval")
	}
	// The creator cannot approve their own report even as a manager (four-eyes keys on created_by).
	creatorMgr := auth.Principal{UserID: creator.UserID, TenantID: tid, Role: auth.RoleSOCManager, Email: "cm@rep"}
	if _, err := svc.Approve(ctx, creatorMgr, rep.ID); err == nil {
		t.Fatal("the report creator must not be able to approve their own report")
	}
	// A junior (distinct user) cannot approve.
	junior := auth.Principal{UserID: uuid.New(), TenantID: tid, Role: auth.RoleAnalystT1, Email: "j@rep"}
	if _, err := svc.Approve(ctx, junior, rep.ID); err == nil {
		t.Fatal("a junior analyst must not be able to approve a report")
	}
	// Still undownloadable after the failed attempts.
	if _, _, err := svc.Download(ctx, creator, rep.ID); err == nil {
		t.Fatal("report must remain undownloadable after rejected approval attempts")
	}
	// A distinct soc_manager approves → releasable, approver recorded.
	mgr := managerActor(tid)
	approved, err := svc.Approve(ctx, mgr, rep.ID)
	if err != nil {
		t.Fatalf("a distinct soc_manager must be able to approve: %v", err)
	}
	if approved.ReviewStatus != "approved" || approved.ReviewedBy == nil || *approved.ReviewedBy != mgr.UserID {
		t.Fatalf("approved report must record approver: %+v", approved)
	}
	if _, _, err := svc.Download(ctx, creator, rep.ID); err != nil {
		t.Fatalf("an approved report must be downloadable: %v", err)
	}
	// Double-approval is a no-op → 409 (atomic WHERE guard).
	if _, err := svc.Approve(ctx, managerActor(tid), rep.ID); err == nil {
		t.Fatal("re-approving a decided report must be refused (atomic state guard)")
	}
	if n := auditCount(t, db, tid, "approve"); n != 1 {
		t.Fatalf("expected exactly 1 approve audit row, got %d", n)
	}
}

// A rejected report is terminally non-releasable and cannot be flipped back to approved.
func TestReportApproval_RejectIsTerminal(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvcBreach(t, db)
	ctx := context.Background()

	creator := repActor(tid)
	incID := seedBreachIncident(t, db, tid, "unauthorized access")
	rep, err := svc.GenerateBreachReport(ctx, creator, incID, FormatCSV)
	if err != nil {
		t.Fatalf("generate breach: %v", err)
	}
	mgr := managerActor(tid)
	rejected, err := svc.Reject(ctx, mgr, rep.ID, "figures not reconciled")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.ReviewStatus != "rejected" || rejected.ReviewNote != "figures not reconciled" {
		t.Fatalf("rejected report must record status + reason: %+v", rejected)
	}
	if _, _, err := svc.Download(ctx, creator, rep.ID); err == nil {
		t.Fatal("a rejected report must NOT be downloadable")
	}
	// Cannot approve after reject (terminal — the atomic guard only fires from pending_review).
	if _, err := svc.Approve(ctx, managerActor(tid), rep.ID); err == nil {
		t.Fatal("a rejected report must not be approvable (terminal)")
	}
	if n := auditCount(t, db, tid, "reject"); n != 1 {
		t.Fatalf("expected exactly 1 reject audit row, got %d", n)
	}
}

// A non-review type (service_review, seeded review_required=false) stays downloadable with no approval — backward-
// compatible with slice A.
func TestReportApproval_NonReviewTypeUnaffected(t *testing.T) {
	db := repDB(t)
	tid := repTenant(t, db)
	svc := repSvc(t, db)
	ctx := context.Background()

	rep, err := svc.Generate(ctx, repActor(tid), "service_review", FormatCSV)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if rep.ReviewStatus != "none" {
		t.Fatalf("a non-review type must land review_status=none, got %q", rep.ReviewStatus)
	}
	if _, _, err := svc.Download(ctx, repActor(tid), rep.ID); err != nil {
		t.Fatalf("a non-review report must download without approval: %v", err)
	}
}

// The pending-approval queue is senior-gated and tenant-confined, and lists only pending_review reports.
func TestReportApproval_PendingQueue(t *testing.T) {
	db := repDB(t)
	a := repTenant(t, db)
	b := repTenant(t, db)
	svc := repSvcBreach(t, db)
	ctx := context.Background()

	incID := seedBreachIncident(t, db, a, "unauthorized access")
	repA, err := svc.GenerateBreachReport(ctx, repActor(a), incID, FormatCSV)
	if err != nil {
		t.Fatalf("generate breach: %v", err)
	}
	// A junior cannot read the queue.
	if _, err := svc.ListPendingApproval(ctx, repActor(a)); err == nil {
		t.Fatal("a junior must not read the pending-approval queue")
	}
	// The manager of tenant A sees exactly the one pending report.
	q, err := svc.ListPendingApproval(ctx, managerActor(a))
	if err != nil {
		t.Fatalf("manager queue: %v", err)
	}
	if len(q) != 1 || q[0].ID != repA.ID {
		t.Fatalf("tenant A queue must hold exactly its pending report, got %+v", q)
	}
	// A manager of tenant B sees nothing of tenant A's queue (RLS).
	qb, err := svc.ListPendingApproval(ctx, managerActor(b))
	if err != nil {
		t.Fatalf("tenant B queue: %v", err)
	}
	if len(qb) != 0 {
		t.Fatalf("tenant B must not see tenant A's pending report, got %+v", qb)
	}
	// Cross-tenant approve of A's report by B resolves to not-found (RLS).
	if _, err := svc.Approve(ctx, managerActor(b), repA.ID); err == nil {
		t.Fatal("a cross-tenant manager must not approve another tenant's report")
	}
}
