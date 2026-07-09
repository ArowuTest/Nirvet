package detection_test

// §6.6 slice C (DET-005/007/009) against a migrated Postgres. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDetectionSliceC(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run detection slice C tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "detc-" + uuid.NewString()})

	repo := detection.NewRepository(db)
	engine := detection.NewEngine(repo)
	svc := detection.NewService(repo, engine)
	actor := uuid.New()

	// A native rule authored in draft, advanced to pilot.
	rule, err := svc.Create(ctx, tn.ID, detection.CreateInput{
		Name: "malware-name", Severity: "high", Confidence: 70, Stage: "draft",
		Condition: detection.Condition{All: []detection.Predicate{{Field: "class_name", Op: detection.OpContains, Value: "malware"}}},
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	for _, to := range []string{"peer_review", "qa", "pilot"} {
		if err := svc.Transition(ctx, tn.ID, rule.ID, to, "advance", actor, false); err != nil {
			t.Fatalf("transition %s: %v", to, err)
		}
	}

	// DET-005 promotion gate: pilot -> production is BLOCKED while the rule has no passing tests.
	if err := svc.Transition(ctx, tn.ID, rule.ID, "production", "", actor, false); err == nil {
		t.Fatal("promotion to production must be blocked with no test cases")
	}

	// Add a passing test case; RunTests reports all-pass; promotion now succeeds.
	if _, err := svc.AddTestCase(ctx, tn.ID, rule.ID, detection.AddTestCaseInput{
		Name: "hit", Sample: detection.SampleEvent{ClassName: "generic malware sig"}, ExpectedMatch: true,
	}, actor); err != nil {
		t.Fatalf("add test case: %v", err)
	}
	run, err := svc.RunTests(ctx, tn.ID, rule.ID)
	if err != nil || !run.AllPass || run.Total != 1 {
		t.Fatalf("expected 1/1 all-pass, got %+v (err %v)", run, err)
	}
	if err := svc.Transition(ctx, tn.ID, rule.ID, "production", "tested", actor, false); err != nil {
		t.Fatalf("promotion after passing tests must succeed: %v", err)
	}

	// A rule with a FAILING test stays blocked from production.
	r2, _ := svc.Create(ctx, tn.ID, detection.CreateInput{
		Name: "blocked", Severity: "low", Stage: "draft",
		Condition: detection.Condition{All: []detection.Predicate{{Field: "source", Op: detection.OpEq, Value: "zzz"}}},
	})
	for _, to := range []string{"peer_review", "qa", "pilot"} {
		_ = svc.Transition(ctx, tn.ID, r2.ID, to, "", actor, false)
	}
	// Expect match on source!="zzz" → actual false, expected true → the test fails.
	_, _ = svc.AddTestCase(ctx, tn.ID, r2.ID, detection.AddTestCaseInput{
		Name: "wrong", Sample: detection.SampleEvent{Source: "other"}, ExpectedMatch: true}, actor)
	if err := svc.Transition(ctx, tn.ID, r2.ID, "production", "", actor, false); err == nil {
		t.Fatal("promotion must be blocked when a test case fails")
	}

	// DET-009 coverage: give the promoted rule a data-source dependency that is NOT being ingested.
	if err := svc.SetMetadata(ctx, tn.ID, rule.ID, nil, []string{"defender", "m365"}); err != nil {
		t.Fatalf("set metadata: %v", err)
	}
	gaps, err := svc.CoverageGaps(ctx, tn.ID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.RuleID == rule.ID {
			found = true
			if len(g.MissingDeps) != 2 {
				t.Fatalf("expected both deps missing (no ingestion), got %v", g.MissingDeps)
			}
		}
	}
	if !found {
		t.Fatal("expected a coverage gap for the rule with unfed dependencies")
	}

	// M3: once a source is ingested (recorded in tenant_ingested_sources), it drops off the gap list.
	if err := db.WithTenant(ctx, tn.ID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO tenant_ingested_sources (tenant_id, source) VALUES ($1,'defender')`, tn.ID)
		return e
	}); err != nil {
		t.Fatalf("seed ingested source: %v", err)
	}
	gaps2, err := svc.CoverageGaps(ctx, tn.ID)
	if err != nil {
		t.Fatalf("coverage2: %v", err)
	}
	for _, g := range gaps2 {
		if g.RuleID == rule.ID {
			if len(g.MissingDeps) != 1 || g.MissingDeps[0] != "m365" {
				t.Fatalf("after ingesting 'defender', only 'm365' should be missing, got %v", g.MissingDeps)
			}
		}
	}

	// M2: loosening require_tests_for_production is senior-only (a detEng can't disable the guardrail
	// it is also subject to). isSenior=false must be rejected; isSenior=true allowed.
	if _, err := svc.SetSettings(ctx, tn.ID, detection.Settings{
		FPRateThreshold: 0.5, MinFeedbackSample: 1, CoverageWindowDays: 7, RequireTestsForProduction: false,
	}, false); err == nil {
		t.Fatal("non-senior must not be able to disable require_tests_for_production")
	}
	if _, err := svc.SetSettings(ctx, tn.ID, detection.Settings{
		FPRateThreshold: 0.5, MinFeedbackSample: 1, CoverageWindowDays: 7, RequireTestsForProduction: false,
	}, true); err != nil {
		t.Fatalf("senior should be able to loosen the guardrail: %v", err)
	}
	// Restore the guardrail (tightening is open to non-senior).
	if _, err := svc.SetSettings(ctx, tn.ID, detection.Settings{
		FPRateThreshold: 0.5, MinFeedbackSample: 1, CoverageWindowDays: 7, RequireTestsForProduction: true,
	}, false); err != nil {
		t.Fatalf("non-senior should be able to tighten the guardrail: %v", err)
	}

	// DET-007 feedback loop: an alert from this rule, dispositioned false_positive, is fed back.
	alertSvc := alert.NewService(alert.NewRepository(db)).WithFeedbackSink(svc)
	ev := eventstore.NormalizedEvent{ID: uuid.New(), TenantID: tn.ID, Source: "s", Severity: "high", ClassName: "malware x"}
	a, inserted, err := alertSvc.CreateFromEvent(ctx, ev, alert.Spec{
		Title: "t", Severity: "high", Confidence: 70, DedupeKey: "dc-" + uuid.NewString(), DetectionID: &rule.ID,
	})
	if err != nil || !inserted {
		t.Fatalf("create alert: inserted=%v err=%v", inserted, err)
	}
	if err := alertSvc.Disposition(ctx, tn.ID, a.ID, "false_positive", "noisy", actor); err != nil {
		t.Fatalf("disposition: %v", err)
	}
	// Alert is closed.
	if got, _ := alertSvc.Get(ctx, tn.ID, a.ID); got == nil || string(got.Status) != "closed" {
		t.Fatalf("alert should be closed after disposition, got %+v", got)
	}
	// Detection feedback recorded + surfaced as an FP.
	stats, err := svc.RuleFeedbackStats(ctx, tn.ID, rule.ID)
	if err != nil || stats.Total != 1 || stats.FalsePositives != 1 || stats.FPRate != 1.0 {
		t.Fatalf("expected 1 FP at rate 1.0, got %+v (err %v)", stats, err)
	}

	// Settings round-trip (config-first). Lower the min sample so this single FP triggers the tuning view.
	if _, err := svc.SetSettings(ctx, tn.ID, detection.Settings{
		FPRateThreshold: 0.5, MinFeedbackSample: 1, CoverageWindowDays: 7, RequireTestsForProduction: true,
	}, true); err != nil {
		t.Fatalf("set settings: %v", err)
	}
	tuning, err := svc.TuningView(ctx, tn.ID)
	if err != nil || len(tuning) != 1 {
		t.Fatalf("expected 1 rule needing tuning after lowering min sample, got %d (err %v)", len(tuning), err)
	}

	// Tenant isolation: another tenant cannot see this rule's test cases or add one.
	other, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "detc-other-" + uuid.NewString()})
	if cs, _ := svc.ListTestCases(ctx, other.ID, rule.ID); len(cs) != 0 {
		t.Fatal("cross-tenant must not see test cases")
	}
	if _, err := svc.AddTestCase(ctx, other.ID, rule.ID, detection.AddTestCaseInput{Name: "x", ExpectedMatch: true}, actor); err == nil {
		t.Fatal("cross-tenant AddTestCase must fail (rule not visible)")
	}
	if st, _ := svc.RuleFeedbackStats(ctx, other.ID, rule.ID); st.Total != 0 {
		t.Fatal("cross-tenant must not see feedback")
	}
}
