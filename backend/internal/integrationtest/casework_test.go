package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

// TestIntegration_CaseworkSliceB exercises §6.8 slice B against a real migrated Postgres: tasks
// (CASE-005), config-driven categories (CASE-007), and parent/child + major incidents (CASE-006) with
// the cycle + cross-tenant guards.
func TestIntegration_CaseworkSliceB(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run integration tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tenSvc := tenant.NewService(tenant.NewRepository(db))
	tnA, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "case-A-" + uuid.NewString()})
	tnB, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "case-B-" + uuid.NewString()})

	repo := incident.NewRepository(db)
	svc := incident.NewService(repo, nil, nil)
	pA := auth.Principal{UserID: uuid.New(), TenantID: tnA.ID, Role: auth.RoleAnalystT1, Email: "a@t"}
	pB := auth.Principal{UserID: uuid.New(), TenantID: tnB.ID, Role: auth.RoleAnalystT1, Email: "b@t"}

	newInc := func(tid uuid.UUID, title string) uuid.UUID {
		inc := &incident.Incident{ID: uuid.New(), TenantID: tid, Title: title, Severity: "high",
			Category: "uncategorised", Stage: incident.StageTriage}
		seed := &incident.TimelineEntry{ID: uuid.New(), Author: "system", Kind: "status", Note: "opened"}
		if err := repo.CreateWithSeed(ctx, tid, inc, seed); err != nil {
			t.Fatalf("create incident: %v", err)
		}
		return inc.ID
	}

	parent := newInc(tnA.ID, "Umbrella")
	child := newInc(tnA.ID, "Child A")
	foreign := newInc(tnB.ID, "Tenant B incident")

	// CASE-005 tasks: create + list + status update writes a completed_at on done.
	task, err := svc.CreateTask(ctx, pA, parent, incident.TaskInput{Title: "Collect host logs"})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	tasks, _ := svc.ListTasks(ctx, tnA.ID, parent)
	if len(tasks) != 1 || tasks[0].Status != incident.TaskOpen {
		t.Fatalf("expected 1 open task, got %+v", tasks)
	}
	if err := svc.UpdateTaskStatus(ctx, pA, task.ID, incident.TaskDone); err != nil {
		t.Fatalf("update task: %v", err)
	}
	tasks, _ = svc.ListTasks(ctx, tnA.ID, parent)
	if tasks[0].Status != incident.TaskDone || tasks[0].CompletedAt == nil {
		t.Fatalf("done task must stamp completed_at: %+v", tasks[0])
	}
	if err := svc.UpdateTaskStatus(ctx, pA, task.ID, "bogus"); err == nil {
		t.Fatal("invalid task status must be rejected")
	}

	// CASE-007 categories: seeded set visible; valid key accepted, unknown rejected.
	cats, err := svc.ListCategories(ctx, tnA.ID)
	if err != nil || len(cats) < 5 {
		t.Fatalf("expected seeded categories, got %d (%v)", len(cats), err)
	}
	if err := svc.SetCategory(ctx, pA, child, "phishing"); err != nil {
		t.Fatalf("set valid category: %v", err)
	}
	if err := svc.SetCategory(ctx, pA, child, "not_a_category"); err == nil {
		t.Fatal("unknown category must be rejected")
	}

	// CASE-006 parent/child: link, list children, reject self-parent, reject cycle, reject cross-tenant.
	if err := svc.LinkParent(ctx, pA, child, parent); err != nil {
		t.Fatalf("link parent: %v", err)
	}
	kids, _ := svc.Children(ctx, tnA.ID, parent)
	if len(kids) != 1 || kids[0].ID != child {
		t.Fatalf("expected child under parent, got %+v", kids)
	}
	if err := svc.LinkParent(ctx, pA, parent, parent); err == nil {
		t.Fatal("self-parent must be rejected")
	}
	// Cycle: parent already has child as descendant; linking parent under child must be rejected.
	if err := svc.LinkParent(ctx, pA, parent, child); err == nil {
		t.Fatal("cycle must be rejected")
	}
	// Cross-tenant: tenant A cannot link a tenant B incident as parent.
	if err := svc.LinkParent(ctx, pA, child, foreign); err == nil {
		t.Fatal("cross-tenant parent must be rejected")
	}
	// Unlink.
	if err := svc.UnlinkParent(ctx, pA, child); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	kids, _ = svc.Children(ctx, tnA.ID, parent)
	if len(kids) != 0 {
		t.Fatalf("child should be unlinked, got %+v", kids)
	}

	// CASE-006 major flag persists on the detail view.
	if err := svc.SetMajor(ctx, pA, parent, true); err != nil {
		t.Fatalf("set major: %v", err)
	}
	got, _ := svc.Get(ctx, tnA.ID, parent)
	if !got.IsMajor {
		t.Fatal("incident should be flagged major")
	}

	// Tenant isolation: tenant B cannot see tenant A's tasks.
	bTasks, _ := svc.ListTasks(ctx, tnB.ID, parent)
	if len(bTasks) != 0 {
		t.Fatalf("tenant B must not see tenant A tasks, got %+v", bTasks)
	}
	_ = pB
}
