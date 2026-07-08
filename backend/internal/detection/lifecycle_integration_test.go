package detection_test

// Detection-as-code lifecycle (§6.6 slice B) against a migrated Postgres. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func TestDetectionLifecycle(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run detection lifecycle tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "det-" + uuid.NewString()})

	repo := detection.NewRepository(db)
	engine := detection.NewEngine(repo)
	svc := detection.NewService(repo, engine)
	actor := uuid.New()

	// A rule created in DRAFT must NOT fire (not lifecycle-active).
	src := "svc-" + uuid.NewString()
	rule, err := svc.CreateCELRule(ctx, tn.ID, detection.CELRuleInput{
		Name: "draft-rule", Severity: "high", Confidence: 80,
		Expression: `event.source == "` + src + `"`, Stage: "draft",
	})
	if err != nil {
		t.Fatalf("create draft rule: %v", err)
	}
	if rule.Stage != "draft" || rule.Version != 1 {
		t.Fatalf("expected draft/v1, got %s/v%d", rule.Stage, rule.Version)
	}
	ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: tn.ID, Source: src, Severity: "high"}
	if m, _ := engine.Evaluate(ctx, tn.ID, ev); len(m) != 0 {
		t.Fatalf("draft rule must not fire, got %d matches", len(m))
	}

	// Promote draft -> peer_review -> qa -> pilot (version bumps each time); at pilot it fires.
	for _, to := range []string{"peer_review", "qa", "pilot"} {
		if err := svc.Transition(ctx, tn.ID, rule.ID, to, "advance", actor, false); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
	if m, _ := engine.Evaluate(ctx, tn.ID, ev); len(m) != 1 {
		t.Fatalf("pilot rule should fire once, got %d", len(m))
	}
	// An illegal jump (pilot -> draft) is rejected.
	if err := svc.Transition(ctx, tn.ID, rule.ID, "draft", "", actor, false); err == nil {
		t.Fatal("pilot -> draft must be rejected")
	}

	// Version history accumulated across transitions; roll back to the earliest.
	vers, err := svc.Versions(ctx, tn.ID, rule.ID)
	if err != nil || len(vers) < 3 {
		t.Fatalf("expected >=3 version snapshots, got %d (%v)", len(vers), err)
	}
	if err := svc.Rollback(ctx, tn.ID, rule.ID, 1, actor); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Metadata: owner + declared data-source dependencies.
	owner := uuid.New()
	if err := svc.SetMetadata(ctx, tn.ID, rule.ID, &owner, []string{"m365", "defender"}); err != nil {
		t.Fatalf("set metadata: %v", err)
	}

	// Emergency deploy from qa straight to production (a fresh rule).
	r2, _ := svc.CreateCELRule(ctx, tn.ID, detection.CELRuleInput{
		Name: "emergency", Severity: "critical", Confidence: 90, Expression: `event.severity == "critical"`, Stage: "draft",
	})
	_ = svc.Transition(ctx, tn.ID, r2.ID, "peer_review", "", actor, false)
	_ = svc.Transition(ctx, tn.ID, r2.ID, "qa", "", actor, false)
	if err := svc.Transition(ctx, tn.ID, r2.ID, "production", "incident response", actor, true); err != nil {
		t.Fatalf("emergency deploy: %v", err)
	}

	// Retire the first rule → it stops firing.
	if err := svc.Transition(ctx, tn.ID, rule.ID, "retired", "obsolete", actor, false); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if m, _ := engine.Evaluate(ctx, tn.ID, ev); len(m) != 0 {
		t.Fatalf("retired rule must not fire, got %d", len(m))
	}

	// Tenant isolation: another tenant cannot transition this rule.
	other, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "det-other-" + uuid.NewString()})
	if err := svc.Transition(ctx, other.ID, rule.ID, "draft", "", actor, false); err == nil {
		t.Fatal("cross-tenant transition must fail")
	}
}
