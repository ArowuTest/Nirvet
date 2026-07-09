package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/compliance"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

// TestIntegration_ComplianceAssessment exercises §6.14 against a real migrated Postgres: seeded global
// frameworks/controls are visible, Assess produces a per-control status from live state, a manual
// override persists and wins over the auto signal, and tenant status is isolated.
func TestIntegration_ComplianceAssessment(t *testing.T) {
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
	tnA, err := tenSvc.Create(ctx, tenant.CreateInput{Name: "comp-A-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	tnB, err := tenSvc.Create(ctx, tenant.CreateInput{Name: "comp-B-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}

	svc := compliance.NewService(compliance.NewRepository(db))

	// Seeded global frameworks are visible to a tenant.
	fws, err := svc.ListFrameworks(ctx, tnA.ID)
	if err != nil {
		t.Fatalf("list frameworks: %v", err)
	}
	if !hasFramework(fws, "nist_csf_2_0") || !hasFramework(fws, "cis_v8_1") {
		t.Fatalf("expected seeded global frameworks, got %+v", fws)
	}

	// R5-M3: auto-signals measure the tenant's OWN posture, not the global seed catalogue. A fresh
	// tenant with no own detection rules → DETECT gap.
	cov, err := svc.Assess(ctx, tnA.ID, "nist_csf_2_0")
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if len(cov.Functions) != 6 {
		t.Fatalf("expected 6 NIST functions, got %d", len(cov.Functions))
	}
	rc := functionByRef(cov, "RC")
	if rc == nil || rc.Status != compliance.StatusGap {
		t.Fatalf("RECOVER should roll up to gap (not_implemented), got %+v", rc)
	}
	if de := functionByRef(cov, "DE"); de == nil || de.Status != compliance.StatusGap {
		t.Fatalf("DETECT should be gap for a tenant with no OWN detection rules (M3), got %+v", de)
	}

	// After the tenant authors its OWN enabled detection rule, DETECT becomes met (own-posture signal).
	detSvc := detection.NewService(detection.NewRepository(db), detection.NewEngine(detection.NewRepository(db)))
	if _, err := detSvc.CreateCELRule(ctx, tnA.ID, detection.CELRuleInput{
		Name: "own-rule", Severity: "high", Confidence: 70, Expression: `event.severity == "high"`,
	}); err != nil {
		t.Fatalf("create own detection rule: %v", err)
	}
	cov, err = svc.Assess(ctx, tnA.ID, "nist_csf_2_0")
	if err != nil {
		t.Fatalf("re-assess: %v", err)
	}
	de := functionByRef(cov, "DE")
	if de == nil || de.Status != compliance.StatusMet {
		t.Fatalf("DETECT should be met once the tenant has its own detection rule, got %+v", de)
	}

	// R6-C3: flat-seeded frameworks (CIS v8.1) must produce a real score — every control is a childless
	// top-level control with a signal, and must be assessed as its own leaf (not a null rollup → 0).
	cis, err := svc.Assess(ctx, tnA.ID, "cis_v8_1")
	if err != nil {
		t.Fatalf("assess CIS: %v", err)
	}
	if len(cis.Functions) == 0 || cis.Score == 0 {
		t.Fatalf("CIS v8.1 must score (flat framework), got %d functions score=%d", len(cis.Functions), cis.Score)
	}
	metOrGap := 0
	for _, f := range cis.Functions {
		if f.Status != compliance.StatusNotApplicable {
			metOrGap++
		}
	}
	if metOrGap == 0 {
		t.Fatal("CIS controls must be assessed (not all not_applicable)")
	}

	// Manual override wins over the auto signal and persists. Override RC.RP → met.
	if err := svc.SetControlStatus(ctx, tnA.ID, compliance.SetStatusInput{
		FrameworkKey: "nist_csf_2_0", ControlRef: "RC.RP", Status: compliance.StatusMet,
		Note: "DR runbook attached", EvidenceRef: "runbook-2026",
	}, uuid.New()); err != nil {
		t.Fatalf("set status: %v", err)
	}
	cov2, err := svc.Assess(ctx, tnA.ID, "nist_csf_2_0")
	if err != nil {
		t.Fatalf("re-assess: %v", err)
	}
	rp := controlByRef(functionByRef(cov2, "RC"), "RC.RP")
	if rp == nil || rp.Status != compliance.StatusMet || rp.Source != "manual" {
		t.Fatalf("manual override should win: %+v", rp)
	}

	// Rejects an unknown control and an invalid status.
	if err := svc.SetControlStatus(ctx, tnA.ID, compliance.SetStatusInput{FrameworkKey: "nist_csf_2_0", ControlRef: "NOPE", Status: compliance.StatusMet}, uuid.New()); err == nil {
		t.Fatal("expected error for unknown control")
	}
	if err := svc.SetControlStatus(ctx, tnA.ID, compliance.SetStatusInput{FrameworkKey: "nist_csf_2_0", ControlRef: "RC.RP", Status: "bogus"}, uuid.New()); err == nil {
		t.Fatal("expected error for invalid status")
	}

	// Tenant isolation: B's assessment of RC.RP is NOT the manual override A set (B stays auto/gap).
	covB, err := svc.Assess(ctx, tnB.ID, "nist_csf_2_0")
	if err != nil {
		t.Fatalf("assess B: %v", err)
	}
	rpB := controlByRef(functionByRef(covB, "RC"), "RC.RP")
	if rpB == nil || rpB.Source != "auto" || rpB.Status != compliance.StatusGap {
		t.Fatalf("tenant B must not see tenant A's manual override: %+v", rpB)
	}
}

func hasFramework(fws []compliance.Framework, key string) bool {
	for _, f := range fws {
		if f.Key == key {
			return true
		}
	}
	return false
}

func functionByRef(cov *compliance.Coverage, ref string) *compliance.FunctionAssessment {
	for i := range cov.Functions {
		if cov.Functions[i].ControlRef == ref {
			return &cov.Functions[i]
		}
	}
	return nil
}

func controlByRef(fn *compliance.FunctionAssessment, ref string) *compliance.ControlAssessment {
	if fn == nil {
		return nil
	}
	for i := range fn.Controls {
		if fn.Controls[i].ControlRef == ref {
			return &fn.Controls[i]
		}
	}
	return nil
}
