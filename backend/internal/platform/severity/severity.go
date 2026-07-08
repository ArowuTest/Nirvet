// Package severity is the single source of truth for Nirvet's canonical severity scale
// (SRS §10.2: P5 informational .. P1 critical). Every domain that ranks or compares
// severities imports this instead of re-encoding the ordering map (Phase 0 hygiene —
// it was previously duplicated in incident, correlation, entitygraph, tenant and asset).
// Pure leaf package with no dependencies, so any package can use it without import cycles.
package severity

// Canonical severity levels, ordered worst-last. These are the string values used
// throughout the platform (matching the DB CHECK constraints).
const (
	Informational = "informational"
	Low           = "low"
	Medium        = "medium"
	High          = "high"
	Critical      = "critical"
)

// rank orders the scale; higher = worse. Unknown/blank values are handled in Rank.
var rank = map[string]int{
	Informational: 0,
	Low:           1,
	Medium:        2,
	High:          3,
	Critical:      4,
}

// Rank returns the canonical ordering of a severity (0=informational .. 4=critical). An
// unknown or blank value returns -1, so an unrecognised severity always ranks below every
// real one and can never accidentally outrank a genuine severity in a comparison.
func Rank(s string) int {
	if r, ok := rank[s]; ok {
		return r
	}
	return -1
}

// Valid reports whether s is a canonical severity.
func Valid(s string) bool { _, ok := rank[s]; return ok }

// Worse returns the more severe of a and b (b wins only when strictly worse than a, so the
// result is stable for equal ranks).
func Worse(a, b string) string {
	if Rank(b) > Rank(a) {
		return b
	}
	return a
}
