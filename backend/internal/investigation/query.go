package investigation

// §6.9 #124 I-1 — the hunt-query model + validation. The model is DELIBERATELY flat (an All list AND-ed, an Any list
// OR-ed) — there is no recursive/nested predicate tree, so the parser/planner blow-up of arbitrary nesting is
// impossible by construction (must-add #4, nesting half). The count half is the MaxPredicates cap below. A bounded
// time window is MANDATORY and binds to the indexed `observed_at` column (must-add #5) so the cost ceiling is real,
// not a limit behind a seq-scan.

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// Predicate is one field/op/value comparison. Field and Op are validated against the code-owned registry; Value is
// only ever bound as a SQL parameter, never concatenated into SQL text.
type Predicate struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value,omitempty"`
}

// HuntQuery is a bounded, allow-listed event search. All predicates are AND-ed; Any predicates are OR-ed; the two
// groups are AND-ed together. From/To bound the mandatory time window (on event_time / observed_at).
type HuntQuery struct {
	All   []Predicate `json:"all,omitempty"`
	Any   []Predicate `json:"any,omitempty"`
	From  time.Time   `json:"from"`
	To    time.Time   `json:"to"`
	Limit int         `json:"limit,omitempty"`
}

// Limits are the cost-ceiling knobs. They are admin-configurable (loaded from a seeded config row by the service) so
// the ceiling is a policy, not a code constant (no-hardcoding); DefaultLimits is the seeded default.
type Limits struct {
	MaxPredicates int           // total across All+Any (must-add #4)
	MaxTimeSpan   time.Duration // widest From..To window (must-add #5)
	DefaultLimit  int           // applied when the query omits Limit
	MaxLimit      int           // hard row cap
}

// DefaultLimits is the seeded default cost ceiling.
func DefaultLimits() Limits {
	return Limits{MaxPredicates: 20, MaxTimeSpan: 90 * 24 * time.Hour, DefaultLimit: 200, MaxLimit: 1000}
}

// Validate checks the query against the registry, the actor's role, and the cost ceiling. It returns a 400/403 API
// error on any violation (fail-closed) and NEVER partially accepts a malformed query. It also normalizes Limit.
func (q *HuntQuery) Validate(actor auth.Principal, lim Limits) error {
	// Mandatory bounded time window on the indexed column (must-add #5).
	if q.From.IsZero() || q.To.IsZero() {
		return httpx.ErrBadRequest("a bounded time window (from, to) is required")
	}
	if !q.To.After(q.From) {
		return httpx.ErrBadRequest("to must be after from")
	}
	if q.To.Sub(q.From) > lim.MaxTimeSpan {
		return httpx.ErrBadRequest("time window exceeds the maximum allowed span")
	}
	// Predicate count cap (must-add #4).
	if len(q.All)+len(q.Any) > lim.MaxPredicates {
		return httpx.ErrBadRequest("too many predicates")
	}
	for _, p := range append(append([]Predicate{}, q.All...), q.Any...) {
		if err := validatePredicate(actor, p); err != nil {
			return err
		}
	}
	// Normalize the row limit.
	if q.Limit <= 0 {
		q.Limit = lim.DefaultLimit
	}
	if q.Limit > lim.MaxLimit {
		q.Limit = lim.MaxLimit
	}
	return nil
}

func validatePredicate(actor auth.Principal, p Predicate) error {
	f, ok := lookupField(p.Field)
	if !ok {
		return httpx.ErrBadRequest("unknown query field: " + p.Field)
	}
	// Field-level visibility (must-add #3): predicating on a field above the actor's role is refused.
	if !roleMeets(actor.Role, f.MinRole) {
		return httpx.ErrForbidden("insufficient role to query field: " + p.Field)
	}
	if !opValidFor(f.Type, p.Op) {
		return httpx.ErrBadRequest("operator " + p.Op + " is not valid for field " + p.Field)
	}
	return validateValue(f.Type, p.Op, p.Value)
}

// validateValue enforces that the JSON value matches the op/field type — so the compiler always binds a well-typed
// parameter (a type confusion can't smuggle a structure the compiler wasn't expecting).
func validateValue(t FieldType, op string, v any) error {
	if op == OpExists {
		return nil // exists takes no value
	}
	if op == OpIn {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			return httpx.ErrBadRequest("the in operator requires a non-empty array value")
		}
		return nil
	}
	switch t {
	case TypeNumeric:
		if _, ok := toNumber(v); !ok {
			return httpx.ErrBadRequest("numeric field requires a number value")
		}
	case TypeTimestamp:
		if _, ok := toTime(v); !ok {
			return httpx.ErrBadRequest("timestamp field requires an RFC3339 time value")
		}
	default: // text, enum, array element
		if _, ok := v.(string); !ok {
			return httpx.ErrBadRequest("field requires a string value")
		}
	}
	return nil
}

func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func toTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
