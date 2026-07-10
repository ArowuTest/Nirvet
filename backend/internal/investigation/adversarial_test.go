package investigation

// §6.9 #124 I-6 — the dedicated adversarial round for the query surface. Each test is one of the attacks the reviewer
// said they would attempt: make a predicate reach SQL text (via field name, op, or `in` array), scan unbounded, or
// exploit `exists`. Cross-tenant reach is proven in the integration tests (hunt + pivot isolation).

import (
	"strings"
	"testing"
)

// A hostile FIELD NAME (not just a value) must be rejected — it never becomes a column.
func TestAdversarial_HostileFieldNameRejected(t *testing.T) {
	from, to := window()
	for _, field := range []string{"actor_ref; DROP TABLE events", "1=1", "severity)--", "data->>'x'"} {
		q := HuntQuery{From: from, To: to, All: []Predicate{{Field: field, Op: OpEq, Value: "x"}}}
		if statusOf(q.Validate(analyst(), DefaultLimits())) != 400 {
			t.Fatalf("hostile field name %q must be rejected 400", field)
		}
	}
}

// A hostile OPERATOR must be rejected — it never becomes SQL.
func TestAdversarial_HostileOpRejected(t *testing.T) {
	from, to := window()
	for _, op := range []string{"eq; DROP", "=", "OR 1=1", ""} {
		q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "severity", Op: op, Value: "high"}}}
		if statusOf(q.Validate(analyst(), DefaultLimits())) != 400 {
			t.Fatalf("hostile operator %q must be rejected 400", op)
		}
	}
}

// A huge requested limit is clamped to MaxLimit — no way to widen the row cap.
func TestAdversarial_LimitClampedToMax(t *testing.T) {
	from, to := window()
	lim := DefaultLimits()
	q := HuntQuery{From: from, To: to, Limit: 1_000_000_000, All: []Predicate{{Field: "severity", Op: OpEq, Value: "high"}}}
	if err := q.Validate(analyst(), lim); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if q.Limit != lim.MaxLimit {
		t.Fatalf("an oversized limit must be clamped to MaxLimit(%d), got %d", lim.MaxLimit, q.Limit)
	}
}

// Hostile members inside an `in` array bind as parameters, never as SQL text.
func TestAdversarial_InArrayBindsAsParams(t *testing.T) {
	from, to := window()
	evil := "high') OR ('1'='1"
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "severity", Op: OpIn, Value: []any{evil, "critical"}}}}
	if err := q.Validate(analyst(), DefaultLimits()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	c := Compile(q)
	if strings.Contains(c.where, evil) || strings.Contains(c.where, "OR ('1'='1") {
		t.Fatalf("injection via in-array reached SQL text: %q", c.where)
	}
	if !strings.Contains(c.where, "= ANY($") {
		t.Fatalf("in must compile to a bound ANY(): %q", c.where)
	}
}

// `exists` compiles to a fixed existence predicate with NO bound value — nothing user-controlled reaches SQL.
func TestAdversarial_ExistsHasNoUserValue(t *testing.T) {
	from, to := window()
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "mitre", Op: OpExists, Value: "ignored'; DROP"}}}
	if err := q.Validate(analyst(), DefaultLimits()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	c := Compile(q)
	if strings.Contains(c.where, "DROP") {
		t.Fatalf("exists must not carry a user value into SQL: %q", c.where)
	}
	// The value argument list should only hold the two time-window bounds (no exists param).
	if len(c.args) != 2 {
		t.Fatalf("exists must add no bound arg; args=%d (want 2 time bounds)", len(c.args))
	}
}
