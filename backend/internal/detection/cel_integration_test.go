package detection_test

// A CEL rule, created via the service, must round-trip through the DB (the new
// expression column) and fire via the engine. Gated on NIRVET_TEST_DATABASE_URL.

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

func TestCELRule_FiresThroughEngine(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run the CEL engine integration test")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "cel-" + uuid.NewString()})
	repo := detection.NewRepository(db)
	engine := detection.NewEngine(repo)
	svc := detection.NewService(repo, engine)

	rule, err := svc.CreateCELRule(ctx, tn.ID, detection.CELRuleInput{
		Name:       "exfil-critical",
		Severity:   "critical",
		Expression: `event.severity == "critical" && event.action == "exfiltration"`,
	})
	if err != nil {
		t.Fatalf("create CEL rule: %v", err)
	}

	// A matching event fires exactly this rule (seeded global rules don't match).
	match := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: tn.ID, Severity: "critical", Action: "exfiltration"}
	fired, err := engine.Evaluate(ctx, tn.ID, match)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	found := false
	for _, m := range fired {
		if m.RuleID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("CEL rule did not fire on a matching event; matches=%+v", fired)
	}

	// A non-matching event (wrong action) must not fire the CEL rule.
	noMatch := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: tn.ID, Severity: "critical", Action: "login"}
	fired2, _ := engine.Evaluate(ctx, tn.ID, noMatch)
	for _, m := range fired2 {
		if m.RuleID == rule.ID {
			t.Fatal("CEL rule fired on a non-matching event")
		}
	}
}
