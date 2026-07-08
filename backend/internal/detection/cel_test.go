package detection

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
)

func celEvent(sev, class string, conf int, data map[string]any) eventstore.NormalizedEvent {
	return eventstore.NormalizedEvent{
		ID: uuid.New(), Severity: sev, ClassName: class, Confidence: conf, Data: data,
	}
}

func TestCEL_CompileAndEval(t *testing.T) {
	// Note: CEL's .contains() is case-sensitive (a deliberate difference from the
	// native `contains` op, which is case-insensitive) — expression + data agree here.
	prog, err := CompileCEL(`event.severity == "critical" && event.class_name.contains("malware")`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !EvalCEL(prog, celEvent("critical", "win32/malware.gen", 0, nil)) {
		t.Error("expected match on critical malware event")
	}
	if EvalCEL(prog, celEvent("low", "win32/malware.gen", 0, nil)) {
		t.Error("low severity must not match")
	}
	if EvalCEL(prog, celEvent("critical", "Recon", 0, nil)) {
		t.Error("non-malware class must not match")
	}
}

func TestCEL_NestedDataAndConfidence(t *testing.T) {
	// Reference the nested data payload and a numeric field.
	prog, err := CompileCEL(`event.data.vendor == "CrowdStrike" && int(event.confidence) >= 80`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !EvalCEL(prog, celEvent("high", "x", 90, map[string]any{"vendor": "CrowdStrike"})) {
		t.Error("expected match: CrowdStrike + confidence 90")
	}
	if EvalCEL(prog, celEvent("high", "x", 50, map[string]any{"vendor": "CrowdStrike"})) {
		t.Error("confidence 50 (< 80) must not match")
	}
	if EvalCEL(prog, celEvent("high", "x", 90, map[string]any{"vendor": "Okta"})) {
		t.Error("wrong vendor must not match")
	}
}

func TestCEL_InvalidExpressionRejected(t *testing.T) {
	if _, err := CompileCEL(`event.severity ===`); err == nil {
		t.Error("syntactically invalid expression must fail to compile")
	}
	// Non-boolean result is rejected (a rule must fire or not).
	if _, err := CompileCEL(`event.severity`); err == nil {
		t.Error("non-bool expression must be rejected")
	}
	if _, err := CompileCEL(``); err == nil {
		t.Error("empty expression must be rejected")
	}
}

// TestCEL_CostLimit: a comprehension over a large vendor-supplied list is cut off by
// the runtime cost limit and treated as "did not fire" (fail-safe), while the same
// expression over a small list evaluates normally (R3 M3 — hot path can't be pinned).
func TestCEL_CostLimit(t *testing.T) {
	prog, err := CompileCEL(`event.data.items.all(x, x == "a")`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Small list: fully evaluated, all elements "a" → fires.
	if !EvalCEL(prog, celEvent("high", "x", 0, map[string]any{"items": []any{"a", "a", "a"}})) {
		t.Fatal("a cheap comprehension over a small list must still evaluate")
	}
	// Huge list: iterating it would exceed the cost budget, so the eval errors and is
	// treated as no-match rather than burning CPU.
	big := make([]any, 300000)
	for i := range big {
		big[i] = "a"
	}
	if EvalCEL(prog, celEvent("high", "x", 0, map[string]any{"items": big})) {
		t.Fatal("an over-budget comprehension must be cut off (no-match), not run to completion")
	}
}

func TestCEL_EvalErrorIsSafe(t *testing.T) {
	// Referencing a missing nested key evaluates to an error at runtime; EvalCEL
	// must treat that as "did not fire" rather than panic.
	prog, err := CompileCEL(`event.data.nope.deeper == "x"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if EvalCEL(prog, celEvent("high", "x", 0, map[string]any{})) {
		t.Error("runtime error should be treated as no-match")
	}
}
