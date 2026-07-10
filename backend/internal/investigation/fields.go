package investigation

// §6.9 #124 I-1 — the hunt-query field registry. This is the injection boundary: an analyst may only reference a
// field that appears in THIS code-owned map, and the map maps a query name to a FIXED real column — user input is
// NEVER used as a column name. The registry is a compile-time constant, not a DB table, so the boundary can never be
// widened at runtime (reviewer must-add #1, same posture as the §6.18 code-owned safety_class / SOAR action catalog).
//
// Each field also carries its TYPE (which bounds the valid operators — must-add #2) and a MinRole (the seam for
// field-level visibility + result masking — must-add #3). Default is LIGHT: every real field is analyst-visible
// (MinRole = analyst_t1) because analysts need the data and the raw event/payload is already role-gated elsewhere.
// The seam exists so PII-masking or tiered visibility later becomes a registry edit, not a compiler retrofit.

import "github.com/ArowuTest/nirvet/internal/platform/auth"

// FieldType bounds which operators are legal for a field (must-add #2).
type FieldType int

const (
	TypeText      FieldType = iota // free-text columns (eq/neq/contains/exists)
	TypeEnum                       // restricted-vocabulary text (eq/neq/in/exists — no substring)
	TypeNumeric                    // integer columns (eq/neq/gte/lte/in/exists)
	TypeTimestamp                  // timestamptz columns (eq/gte/lte)
	TypeArray                      // text[] columns, e.g. mitre (contains/exists)
)

// Field is one queryable column. Column is the REAL SQL column and comes only from this registry — never from user
// input. MinRole gates both predicating on the field and seeing it unmasked in results.
type Field struct {
	Column  string
	Type    FieldType
	MinRole auth.Role
}

// fieldRegistry is the code-owned allow-list. Adding a field is a code change + review, never a runtime config write.
// Query name (left) is the stable API vocabulary; Column (right) is the physical column on `events`.
var fieldRegistry = map[string]Field{
	"severity":    {Column: "severity", Type: TypeEnum, MinRole: auth.RoleAnalystT1},
	"outcome":     {Column: "outcome", Type: TypeEnum, MinRole: auth.RoleAnalystT1},
	"class":       {Column: "class_name", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"activity":    {Column: "activity_name", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"action":      {Column: "action", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"actor_ref":   {Column: "actor_ref", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"target_ref":  {Column: "target_ref", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"source":      {Column: "source", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"vendor":      {Column: "vendor", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"product":     {Column: "product", Type: TypeText, MinRole: auth.RoleAnalystT1},
	"confidence":  {Column: "confidence", Type: TypeNumeric, MinRole: auth.RoleAnalystT1},
	"mitre":       {Column: "mitre", Type: TypeArray, MinRole: auth.RoleAnalystT1},
	"event_time":  {Column: "observed_at", Type: TypeTimestamp, MinRole: auth.RoleAnalystT1},  // when it happened at source (INDEXED)
	"ingest_time": {Column: "collected_at", Type: TypeTimestamp, MinRole: auth.RoleAnalystT1}, // when we received it
}

// Operators (the fixed op vocabulary; must-add #2 binds them per type below).
const (
	OpEq       = "eq"
	OpNeq      = "neq"
	OpContains = "contains"
	OpGte      = "gte"
	OpLte      = "lte"
	OpIn       = "in"
	OpExists   = "exists"
)

// opsByType is the code-owned op allow-list per field type (must-add #2). A mismatch (e.g. `contains` on a numeric,
// `gte` on text) is rejected at validation, not silently compiled.
var opsByType = map[FieldType]map[string]bool{
	TypeText:      {OpEq: true, OpNeq: true, OpContains: true, OpExists: true},
	TypeEnum:      {OpEq: true, OpNeq: true, OpIn: true, OpExists: true},
	TypeNumeric:   {OpEq: true, OpNeq: true, OpGte: true, OpLte: true, OpIn: true, OpExists: true},
	TypeTimestamp: {OpEq: true, OpGte: true, OpLte: true},
	TypeArray:     {OpContains: true, OpExists: true},
}

// lookupField returns a field spec by query name (false if not in the allow-list — fail-closed).
func lookupField(name string) (Field, bool) {
	f, ok := fieldRegistry[name]
	return f, ok
}

// opValidFor reports whether op is permitted for a field type.
func opValidFor(t FieldType, op string) bool {
	return opsByType[t][op]
}

// roleMeets reports whether actor's role is at least the field's MinRole (fail-closed: an unknown role ranks -1 and
// meets no floor). Used for both predicate authorization and result masking.
func roleMeets(actor auth.Role, min auth.Role) bool {
	return auth.RoleRank(actor) >= auth.RoleRank(min)
}
