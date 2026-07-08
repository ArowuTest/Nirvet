package compliance

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestScoreOf(t *testing.T) {
	if scoreOf(StatusMet) != 100 || scoreOf(StatusPartial) != 50 || scoreOf(StatusGap) != 0 || scoreOf(StatusNotApplicable) != 0 {
		t.Fatal("status→score mapping wrong")
	}
}

func TestRollup(t *testing.T) {
	weights := map[string]int{"a": 1, "b": 1, "c": 2}

	// All met → met, score 100.
	kids := []ControlAssessment{{ControlRef: "a", Status: StatusMet, Score: 100}, {ControlRef: "b", Status: StatusMet, Score: 100}}
	if sc, st := rollup(kids, weights); st != StatusMet || sc != 100 {
		t.Fatalf("all-met rollup = %d/%s", sc, st)
	}

	// Mixed → partial. Weighted: a(1)*100 + b(1)*0 + c(2)*50 = 200 / 4 = 50 → partial.
	kids = []ControlAssessment{
		{ControlRef: "a", Status: StatusMet, Score: 100},
		{ControlRef: "b", Status: StatusGap, Score: 0},
		{ControlRef: "c", Status: StatusPartial, Score: 50},
	}
	if sc, st := rollup(kids, weights); st != StatusPartial || sc != 50 {
		t.Fatalf("mixed rollup = %d/%s, want 50/partial", sc, st)
	}

	// not_applicable excluded from denominator: only 'a' counts → 100/met.
	kids = []ControlAssessment{{ControlRef: "a", Status: StatusMet, Score: 100}, {ControlRef: "b", Status: StatusNotApplicable}}
	if sc, st := rollup(kids, weights); st != StatusMet || sc != 100 {
		t.Fatalf("N/A-excluded rollup = %d/%s", sc, st)
	}

	// All N/A → not_applicable, no divide-by-zero.
	kids = []ControlAssessment{{ControlRef: "a", Status: StatusNotApplicable}}
	if sc, st := rollup(kids, weights); st != StatusNotApplicable || sc != 0 {
		t.Fatalf("all-N/A rollup = %d/%s", sc, st)
	}
}

func TestValidStatus(t *testing.T) {
	for _, s := range []string{StatusMet, StatusPartial, StatusGap, StatusNotApplicable} {
		if !validStatus(s) {
			t.Fatalf("%s should be valid", s)
		}
	}
	if validStatus("unknown") || validStatus("") {
		t.Fatal("invalid statuses must be rejected")
	}
}

// TestSignals_HonestGap confirms unbuilt capabilities resolve to gap, never a fabricated met.
func TestSignals_HonestGap(t *testing.T) {
	res := resolveSignal(context.Background(), nil, uuid.New(), Control{AutoSignal: "not_implemented", AutoConfig: map[string]any{"note": "n/a"}})
	if res.Status != StatusGap {
		t.Fatalf("not_implemented must resolve to gap, got %s", res.Status)
	}
	// platform_capability is always met (no DB needed).
	res = resolveSignal(context.Background(), nil, uuid.New(), Control{AutoSignal: "platform_capability", AutoConfig: map[string]any{"note": "RLS"}})
	if res.Status != StatusMet || res.Note != "RLS" {
		t.Fatalf("platform_capability = %+v", res)
	}
	// Unknown/manual signal → gap awaiting assessment.
	res = resolveSignal(context.Background(), nil, uuid.New(), Control{AutoSignal: "manual"})
	if res.Status != StatusGap {
		t.Fatalf("manual signal must default to gap, got %s", res.Status)
	}
}
