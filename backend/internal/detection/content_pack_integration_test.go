package detection_test

// LAUNCH #3 (#186) content-pack landing round (DB-gated on NIRVET_TEST_DATABASE_URL). The seeded global rules
// (migration 0107) are only worth shipping if they actually FIRE on the telemetry they claim to cover — a rule
// that can never fire manufactures false coverage confidence (worse than no rule). These tests synthesize the
// exact normalized Entra events the poller produces and assert every stateful seeded rule fires, and that the
// key simple rules match. Field names mirror the connector normalizers, verified in the migration header.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func contentSetup(t *testing.T) (*detection.Engine, *database.DB, uuid.UUID, context.Context) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	// A fresh tenant sees the GLOBAL seeded rules (RLS: global + own). No tenant rules created — we exercise the
	// shipped content only.
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "content-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return detection.NewEngine(detection.NewRepository(db)), db, tn.ID, ctx
}

func authEvent(tenantID uuid.UUID, user, outcome string, data map[string]any) eventstore.NormalizedEvent {
	return eventstore.NormalizedEvent{
		ID: uuid.New(), TenantID: tenantID, ClassName: "Authentication", Action: "signin",
		ActorRef: "user:" + user, Outcome: outcome, ObservedAt: time.Now(), Data: data,
	}
}

// TestContent_BruteForceRuleFires — 10 failed sign-ins for one user in-window must fire the seeded threshold rule.
func TestContent_BruteForceRuleFires(t *testing.T) {
	engine, _, tid, ctx := contentSetup(t)
	fires := 0
	for i := 0; i < 10; i++ {
		m, err := engine.EvaluateStateful(ctx, tid, authEvent(tid, "brutus", "failure", nil))
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		fires += len(m)
	}
	if fires < 1 {
		t.Fatalf("seeded brute-force rule never fired after 10 failed sign-ins (silently-broken content)")
	}
}

// TestContent_ImpossibleTravelFires — two successful sign-ins from distinct countries must fire the distinct rule.
func TestContent_ImpossibleTravelFires(t *testing.T) {
	engine, _, tid, ctx := contentSetup(t)
	m1, _ := engine.EvaluateStateful(ctx, tid, authEvent(tid, "traveller", "success", map[string]any{"countryOrRegion": "GH"}))
	m2, err := engine.EvaluateStateful(ctx, tid, authEvent(tid, "traveller", "success", map[string]any{"countryOrRegion": "RU"}))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(m1) != 0 {
		t.Fatalf("impossible-travel fired on the first country (should need 2 distinct): %d", len(m1))
	}
	if len(m2) < 1 {
		t.Fatalf("seeded impossible-travel rule never fired on the 2nd distinct country (silently-broken content)")
	}
}

// TestContent_MFAFatigueFires — 5 failed MFA-backed sign-ins for one user must fire the seeded threshold rule.
func TestContent_MFAFatigueFires(t *testing.T) {
	engine, _, tid, ctx := contentSetup(t)
	fires := 0
	for i := 0; i < 5; i++ {
		ev := authEvent(tid, "fatigued", "failure", map[string]any{"mfaAuthMethod": "PhoneAppNotification"})
		m, err := engine.EvaluateStateful(ctx, tid, ev)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		fires += len(m)
	}
	if fires < 1 {
		t.Fatalf("seeded MFA-fatigue rule never fired after 5 failed MFA sign-ins (silently-broken content)")
	}
}

// TestContent_SimpleRulesMatch — the single-event seeded rules match their telemetry via the read-only engine.
func TestContent_SimpleRulesMatch(t *testing.T) {
	engine, _, tid, ctx := contentSetup(t)
	cases := []struct {
		name string
		ev   eventstore.NormalizedEvent
	}{
		{"high-risk user", eventstore.NormalizedEvent{
			ID: uuid.New(), TenantID: tid, ClassName: "Identity Risk", ObservedAt: time.Now(),
			Data: map[string]any{"riskLevel": "high"}}},
		{"privileged role assignment", eventstore.NormalizedEvent{
			ID: uuid.New(), TenantID: tid, ClassName: "Directory Audit", ActivityName: "Add member to role", ObservedAt: time.Now()}},
		{"legacy auth", authEvent(tid, "legacy", "success", map[string]any{"clientAppUsed": "IMAP4"})},
		{"consent grant", eventstore.NormalizedEvent{
			ID: uuid.New(), TenantID: tid, ClassName: "Directory Audit", ActivityName: "Consent to application", ObservedAt: time.Now()}},
	}
	for _, c := range cases {
		m, err := engine.Evaluate(ctx, tid, c.ev)
		if err != nil {
			t.Fatalf("%s: eval: %v", c.name, err)
		}
		if len(m) < 1 {
			t.Fatalf("seeded simple rule for %q did not match its telemetry (silently-broken content)", c.name)
		}
	}
}
