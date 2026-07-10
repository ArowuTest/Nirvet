package investigation

// §6.9 #124 I-1 — the predicate compiler. This is where the security model becomes SQL. Invariants:
//   - the column name comes ONLY from the code-owned registry (never from the request);
//   - every user value becomes a BOUND parameter ($N) — user text never appears in the SQL string;
//   - the mandatory time window binds to `observed_at` (the indexed column, must-add #5), and is emitted FIRST so
//     the planner uses events_tenant_observed rather than scanning.
// Compile assumes the query already passed Validate (fields/ops/roles/types checked); it never sees an unknown field.

import (
	"fmt"
	"strings"
)

// compiled is the WHERE clause + its ordered bind args (excluding LIMIT, which the repo appends).
type compiled struct {
	where string
	args  []any
}

// Compile turns a validated HuntQuery into a parameterized WHERE clause. The time window is always present and first.
func Compile(q HuntQuery) compiled {
	var b strings.Builder
	args := make([]any, 0, len(q.All)+len(q.Any)+2)

	// Time window on the indexed column — always emitted, always bound (must-add #5).
	args = append(args, q.From, q.To)
	b.WriteString("observed_at >= $1 AND observed_at <= $2")

	if frag := compileGroup(q.All, " AND ", &args); frag != "" {
		b.WriteString(" AND (")
		b.WriteString(frag)
		b.WriteString(")")
	}
	if frag := compileGroup(q.Any, " OR ", &args); frag != "" {
		b.WriteString(" AND (")
		b.WriteString(frag)
		b.WriteString(")")
	}
	return compiled{where: b.String(), args: args}
}

// compileGroup joins a predicate list with sep (AND/OR). Each predicate contributes at most one bound param; the
// column is looked up from the registry (guaranteed present post-Validate).
func compileGroup(preds []Predicate, sep string, args *[]any) string {
	parts := make([]string, 0, len(preds))
	for _, p := range preds {
		f, ok := lookupField(p.Field)
		if !ok {
			continue // unreachable post-Validate; skip defensively rather than emit anything user-controlled
		}
		parts = append(parts, compilePredicate(f, p, args))
	}
	return strings.Join(parts, sep)
}

// compilePredicate emits `<column> <sqlop> $N` (or a no-param existence check). The $N index is 1-based over the
// running args slice, so binds stay aligned regardless of group order.
func compilePredicate(f Field, p Predicate, args *[]any) string {
	col := f.Column // from the registry ONLY
	switch p.Op {
	case OpExists:
		switch f.Type {
		case TypeArray:
			return fmt.Sprintf("coalesce(array_length(%s,1),0) > 0", col)
		case TypeNumeric, TypeTimestamp:
			return fmt.Sprintf("%s IS NOT NULL", col)
		default:
			return fmt.Sprintf("%s <> ''", col)
		}
	case OpContains:
		if f.Type == TypeArray {
			*args = append(*args, p.Value)
			return fmt.Sprintf("$%d = ANY(%s)", len(*args), col)
		}
		*args = append(*args, p.Value)
		return fmt.Sprintf("%s ILIKE '%%'||$%d||'%%'", col, len(*args))
	case OpIn:
		// Compare as text so one code path serves both text (severity) and numeric (confidence) columns.
		*args = append(*args, toStringSlice(p.Value))
		return fmt.Sprintf("%s::text = ANY($%d)", col, len(*args))
	case OpEq:
		*args = append(*args, coerce(f, p.Value))
		return fmt.Sprintf("%s = $%d", col, len(*args))
	case OpNeq:
		*args = append(*args, coerce(f, p.Value))
		return fmt.Sprintf("%s <> $%d", col, len(*args))
	case OpGte:
		*args = append(*args, coerce(f, p.Value))
		return fmt.Sprintf("%s >= $%d", col, len(*args))
	case OpLte:
		*args = append(*args, coerce(f, p.Value))
		return fmt.Sprintf("%s <= $%d", col, len(*args))
	}
	// Unreachable post-Validate. Emit a never-true guard rather than anything user-controlled.
	return "false"
}

// coerce converts a validated JSON value to the Go type the column expects, so timestamp/numeric binds compare
// correctly (a timestamptz column against a time.Time, not a raw string). Text values pass through unchanged.
func coerce(f Field, v any) any {
	switch f.Type {
	case TypeTimestamp:
		if t, ok := toTime(v); ok {
			return t
		}
	case TypeNumeric:
		if n, ok := toNumber(v); ok {
			return n
		}
	}
	return v
}

// toStringSlice normalizes an `in` array value to []string for the ANY() bind (Postgres text[] / int cast handled by
// the column). Non-string members are stringified so the bind is always a well-typed array.
func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, fmt.Sprintf("%v", e))
	}
	return out
}
