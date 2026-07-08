package integrationtest

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/compliance"
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

	// Assess NIST CSF: produces 6 functions, a numeric score, and honest per-control status.
	cov, err := svc.Assess(ctx, tnA.ID, "nist_csf_2_0")
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if len(cov.Functions) != 6 {
		t.Fatalf("expected 6 NIST functions, got %d", len(cov.Functions))
	}
	// RECOVER maps to not_implemented → its children are gap, function rolls up to gap.
	rc := functionByRef(cov, "RC")
	if rc == nil || rc.Status != compliance.StatusGap {
		t.Fatalf("RECOVER should roll up to gap (not_implemented), got %+v", rc)
	}
	// DETECT maps to detection_coverage; the platform ships a global rule catalogue → met.
	de := functionByRef(cov, "DE")
	if de == nil || de.Status != compliance.StatusMet {
		t.Fatalf("DETECT should be met via detection coverage, got %+v", de)
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
