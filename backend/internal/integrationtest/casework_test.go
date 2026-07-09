package integrationtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

// TestIntegration_CaseworkSliceB exercises §6.8 slice B against a real migrated Postgres: tasks
// (CASE-005), config-driven categories (CASE-007), and parent/child + major incidents (CASE-006) with
// the cycle + cross-tenant guards.
func TestIntegration_CaseworkSliceB(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
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

// fakeBlob is an in-memory BlobPutter for the attachment test.
type fakeBlob struct{ n int }

func (f *fakeBlob) Put(_ context.Context, tenantID uuid.UUID, key string, _ []byte) (string, error) {
	f.n++
	return "mem://" + tenantID.String() + "/" + key, nil
}

// TestIntegration_CaseworkSliceC exercises §6.8 slice C: attachment chain-of-custody (CASE-008) and
// knowledge-base links (CASE-010).
func TestIntegration_CaseworkSliceC(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tenSvc := tenant.NewService(tenant.NewRepository(db))
	tnA, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "casec-A-" + uuid.NewString()})
	tnB, _ := tenSvc.Create(ctx, tenant.CreateInput{Name: "casec-B-" + uuid.NewString()})

	repo := incident.NewRepository(db)
	svc := incident.NewService(repo, nil, nil).WithBlobStore(&fakeBlob{})
	pA := auth.Principal{UserID: uuid.New(), TenantID: tnA.ID, Role: auth.RoleAnalystT1, Email: "a@t"}

	inc := &incident.Incident{ID: uuid.New(), TenantID: tnA.ID, Title: "Case", Severity: "high",
		Category: "uncategorised", Stage: incident.StageTriage}
	if err := repo.CreateWithSeed(ctx, tnA.ID, inc, &incident.TimelineEntry{ID: uuid.New(), Author: "system", Kind: "status", Note: "opened"}); err != nil {
		t.Fatalf("create incident: %v", err)
	}

	// CASE-008: attachment records a sha256 chain-of-custody digest.
	body := []byte("pcap-bytes-here")
	att, err := svc.RegisterAttachment(ctx, pA, inc.ID, "capture.pcap", "application/vnd.tcpdump.pcap", body, "from EDR")
	if err != nil {
		t.Fatalf("register attachment: %v", err)
	}
	// sha256("pcap-bytes-here") is deterministic; assert the stored digest matches.
	sum := sha256.Sum256(body)
	if att.SHA256 != hex.EncodeToString(sum[:]) || att.SizeBytes != int64(len(body)) {
		t.Fatalf("chain-of-custody digest/size wrong: %+v", att)
	}
	atts, _ := svc.ListAttachments(ctx, tnA.ID, inc.ID)
	if len(atts) != 1 || atts[0].BlobURI == "" {
		t.Fatalf("expected 1 stored attachment, got %+v", atts)
	}
	// Empty body rejected.
	if _, err := svc.RegisterAttachment(ctx, pA, inc.ID, "x", "", nil, ""); err == nil {
		t.Fatal("empty attachment must be rejected")
	}
	// R5 observation: a filename with a path separator is rejected (traversal / stored-XSS).
	if _, err := svc.RegisterAttachment(ctx, pA, inc.ID, "../../etc/passwd", "", []byte("x"), ""); err == nil {
		t.Fatal("filename with path separators must be rejected")
	}

	// CASE-010: seeded global runbooks are visible; link one; it shows on the incident.
	arts, err := svc.ListArticles(ctx, tnA.ID)
	if err != nil || len(arts) < 3 {
		t.Fatalf("expected >=3 global articles, got %d (%v)", len(arts), err)
	}
	if err := svc.LinkArticle(ctx, pA, inc.ID, arts[0].ID); err != nil {
		t.Fatalf("link article: %v", err)
	}
	linked, _ := svc.LinkedArticles(ctx, tnA.ID, inc.ID)
	if len(linked) != 1 || linked[0].ID != arts[0].ID {
		t.Fatalf("expected linked article, got %+v", linked)
	}
	// A tenant-owned article + link.
	own, err := svc.CreateArticle(ctx, pA, incident.ArticleInput{Title: "Internal SOP", Category: "phishing"})
	if err != nil {
		t.Fatalf("create article: %v", err)
	}
	if err := svc.LinkArticle(ctx, pA, inc.ID, own.ID); err != nil {
		t.Fatalf("link own article: %v", err)
	}
	// Unlink.
	if err := svc.UnlinkArticle(ctx, pA, inc.ID, arts[0].ID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	linked, _ = svc.LinkedArticles(ctx, tnA.ID, inc.ID)
	if len(linked) != 1 || linked[0].ID != own.ID {
		t.Fatalf("expected only the own article after unlink, got %+v", linked)
	}

	// Tenant isolation: tenant B cannot see tenant A's attachments or its tenant-owned article.
	bAtts, _ := svc.ListAttachments(ctx, tnB.ID, inc.ID)
	if len(bAtts) != 0 {
		t.Fatalf("tenant B must not see tenant A attachments, got %+v", bAtts)
	}
	bArts, _ := svc.ListArticles(ctx, tnB.ID)
	for _, a := range bArts {
		if a.ID == own.ID {
			t.Fatal("tenant B must not see tenant A's own article")
		}
	}
}
