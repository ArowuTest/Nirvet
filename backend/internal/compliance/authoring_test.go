package compliance

// §6.14 slice B authoring-guardrail tests (DB-free): the honesty rules that keep an authored framework assessable and
// non-misleading are enforced BEFORE any DB write, so they unit-test with a nil repo.

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// validAutoSignal is the honesty gate: only a real resolver / manual / rollup is accepted, so an author can't create a
// control that silently never resolves. It is backed by the live `signals` registry (single source of truth).
func TestValidAutoSignal(t *testing.T) {
	for _, s := range []string{"", "manual", "detection_coverage", "asset_inventory", "incident_response", "not_implemented"} {
		if !validAutoSignal(s) {
			t.Fatalf("expected %q to be a valid auto_signal", s)
		}
	}
	for _, s := range []string{"bogus_signal", "Detection_Coverage", "auto", "met"} {
		if validAutoSignal(s) {
			t.Fatalf("expected %q to be rejected as an auto_signal", s)
		}
	}
}

func TestIsTopLevel(t *testing.T) {
	controls := []Control{
		{ControlRef: "GOV", ParentRef: ""},
		{ControlRef: "GOV.1", ParentRef: "GOV"},
	}
	if !isTopLevel(controls, "GOV") {
		t.Fatal("GOV is a top-level control")
	}
	if isTopLevel(controls, "GOV.1") {
		t.Fatal("GOV.1 is a child, not top-level (a parent must be top-level → ≤2-level nesting)")
	}
	if isTopLevel(controls, "ABSENT") {
		t.Fatal("an absent ref is not a valid parent")
	}
}

func TestCreateFramework_RejectsBadKeyAndName(t *testing.T) {
	s := &Service{} // nil repo — validation returns before any DB call
	ctx, tid := context.Background(), uuid.New()
	if _, err := s.CreateFramework(ctx, tid, FrameworkInput{Key: "BAD KEY", Name: "x"}); err == nil {
		t.Fatal("a non-slug framework key must be rejected")
	}
	if _, err := s.CreateFramework(ctx, tid, FrameworkInput{Key: "gh_cii", Name: "  "}); err == nil {
		t.Fatal("an empty name must be rejected")
	}
}

func TestUpsertControl_RejectsInvalidInput(t *testing.T) {
	s := &Service{} // nil repo — every case below returns before frameworkVisible/DB
	ctx, tid := context.Background(), uuid.New()
	base := ControlInput{FrameworkKey: "sovereign_cii_baseline", ControlRef: "RESP.2.GH", Title: "Report to CSA within 24h", Weight: 3, AutoSignal: "manual"}

	bad := base
	bad.AutoSignal = "bogus_signal"
	if _, err := s.UpsertControl(ctx, tid, bad); err == nil {
		t.Fatal("an unknown auto_signal must be rejected (else the control silently never resolves)")
	}

	bad = base
	bad.Weight = 0
	if _, err := s.UpsertControl(ctx, tid, bad); err == nil {
		t.Fatal("weight 0 must be rejected (must be 1..100)")
	}
	bad = base
	bad.Weight = 101
	if _, err := s.UpsertControl(ctx, tid, bad); err == nil {
		t.Fatal("weight 101 must be rejected")
	}

	bad = base
	bad.ControlRef = "bad ref!"
	if _, err := s.UpsertControl(ctx, tid, bad); err == nil {
		t.Fatal("a non-token control_ref must be rejected")
	}

	bad = base
	bad.FrameworkKey = "BAD KEY"
	if _, err := s.UpsertControl(ctx, tid, bad); err == nil {
		t.Fatal("a non-slug framework_key must be rejected")
	}

	bad = base
	bad.Title = "  "
	if _, err := s.UpsertControl(ctx, tid, bad); err == nil {
		t.Fatal("an empty title must be rejected")
	}
}
