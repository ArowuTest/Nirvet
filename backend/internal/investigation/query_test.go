package investigation

// §6.9 #124 I-1 — pure unit tests for the hunt-query security core (no DB). These are the crux: the query surface is
// the codebase's first user-controlled-predicate surface, so validation + compilation are proven to be allow-listed,
// role-gated, cost-bounded, and — above all — to bind every user value as a parameter, never as SQL text.

import (
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

func analyst() auth.Principal { return auth.Principal{Role: auth.RoleAnalystT1} }
func viewer() auth.Principal  { return auth.Principal{Role: auth.RoleCustomerViewer} }
func window() (time.Time, time.Time) {
	to := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	return to.Add(-24 * time.Hour), to
}

func statusOf(err error) int {
	if e, ok := err.(*httpx.APIError); ok {
		return e.Status
	}
	return 0
}

func TestValidate_RejectsUnknownField(t *testing.T) {
	from, to := window()
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "data->>secret", Op: OpEq, Value: "x"}}}
	if statusOf(q.Validate(analyst(), DefaultLimits())) != 400 {
		t.Fatal("an unknown/unlisted field must be rejected 400 (fail-closed)")
	}
}

func TestValidate_RejectsBadOpForType(t *testing.T) {
	from, to := window()
	// contains is text-only; on a numeric field it must be rejected (must-add #2 type-aware ops).
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "confidence", Op: OpContains, Value: "8"}}}
	if statusOf(q.Validate(analyst(), DefaultLimits())) != 400 {
		t.Fatal("contains on a numeric field must be rejected 400")
	}
}

func TestValidate_RoleGate(t *testing.T) {
	from, to := window()
	// Every investigation field is MinRole analyst_t1; a customer_viewer (rank 0) meets none → 403 (must-add #3).
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "actor_ref", Op: OpEq, Value: "user:jane"}}}
	if statusOf(q.Validate(viewer(), DefaultLimits())) != 403 {
		t.Fatal("a role below a field's MinRole must be refused 403")
	}
	if err := q.Validate(analyst(), DefaultLimits()); err != nil {
		t.Fatalf("an analyst_t1 must be allowed to query an analyst_t1 field: %v", err)
	}
}

func TestValidate_PredicateCap(t *testing.T) {
	from, to := window()
	lim := DefaultLimits()
	lim.MaxPredicates = 3
	q := HuntQuery{From: from, To: to, All: []Predicate{
		{Field: "severity", Op: OpEq, Value: "high"}, {Field: "vendor", Op: OpEq, Value: "a"},
		{Field: "product", Op: OpEq, Value: "b"}, {Field: "source", Op: OpEq, Value: "c"},
	}}
	if statusOf(q.Validate(analyst(), lim)) != 400 {
		t.Fatal("exceeding the predicate cap must be rejected 400 (must-add #4)")
	}
}

func TestValidate_TimeWindow(t *testing.T) {
	lim := DefaultLimits()
	from, to := window()
	cases := []struct {
		name string
		q    HuntQuery
	}{
		{"missing", HuntQuery{}},
		{"inverted", HuntQuery{From: to, To: from}},
		{"too wide", HuntQuery{From: to.Add(-lim.MaxTimeSpan - time.Hour), To: to}},
	}
	for _, c := range cases {
		if statusOf(c.q.Validate(analyst(), lim)) != 400 {
			t.Fatalf("%s time window must be rejected 400 (must-add #5)", c.name)
		}
	}
	// A valid bounded window passes.
	if err := (&HuntQuery{From: from, To: to}).Validate(analyst(), lim); err != nil {
		t.Fatalf("a valid bounded window should pass: %v", err)
	}
}

func TestValidate_ValueTypeMismatch(t *testing.T) {
	from, to := window()
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "confidence", Op: OpEq, Value: "not-a-number"}}}
	if statusOf(q.Validate(analyst(), DefaultLimits())) != 400 {
		t.Fatal("a numeric field with a string value must be rejected 400")
	}
}

// THE crux: a hostile value must land in the bound args, NEVER in the SQL text.
func TestCompile_BindsHostileValueAsParam(t *testing.T) {
	from, to := window()
	evil := "'; DROP TABLE events; --"
	q := HuntQuery{From: from, To: to, All: []Predicate{{Field: "actor_ref", Op: OpContains, Value: evil}}}
	if err := q.Validate(analyst(), DefaultLimits()); err != nil {
		t.Fatalf("precondition: query should validate: %v", err)
	}
	c := Compile(q)
	if strings.Contains(c.where, "DROP TABLE") || strings.Contains(c.where, evil) {
		t.Fatalf("injection: hostile value reached SQL text: %q", c.where)
	}
	found := false
	for _, a := range c.args {
		if s, ok := a.(string); ok && s == evil {
			found = true
		}
	}
	if !found {
		t.Fatal("the hostile value must be present as a BOUND arg")
	}
	if !strings.HasPrefix(c.where, "observed_at >= $1 AND observed_at <= $2") {
		t.Fatalf("the indexed time window must be compiled first: %q", c.where)
	}
	if !strings.Contains(c.where, "actor_ref ILIKE") {
		t.Fatalf("contains should compile to a bound ILIKE on the mapped column: %q", c.where)
	}
}

// The registry maps query names to fixed columns; user field names never appear as columns.
func TestCompile_MapsQueryNamesToColumns(t *testing.T) {
	from, to := window()
	q := HuntQuery{From: from, To: to, All: []Predicate{
		{Field: "class", Op: OpEq, Value: "Process Activity"},
		{Field: "event_time", Op: OpGte, Value: from.Format(time.RFC3339)},
		{Field: "mitre", Op: OpContains, Value: "T1059"},
	}}
	if err := q.Validate(analyst(), DefaultLimits()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	c := Compile(q)
	if !strings.Contains(c.where, "class_name = $") {
		t.Fatalf("query name 'class' must map to column class_name: %q", c.where)
	}
	if !strings.Contains(c.where, "$3 = ANY(mitre)") && !strings.Contains(c.where, "ANY(mitre)") {
		t.Fatalf("mitre contains must compile to a bound ANY over the array column: %q", c.where)
	}
	// The mapped timestamp column, bound as a real time.Time (not the raw string).
	if !strings.Contains(c.where, "observed_at >= $") {
		t.Fatalf("event_time gte must map to observed_at: %q", c.where)
	}
}
