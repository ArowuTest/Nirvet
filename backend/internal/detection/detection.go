// Package detection is the detection-engineering engine (SRS §6.6; doc 04).
// Rules are condition-based (a portable subset of Sigma-style matching) with
// MITRE mapping and severity. Global rules (tenant_id NULL) apply to all tenants;
// tenants may add their own. The ingestion worker evaluates every new event
// against the catalogue and raises an alert per match (idempotent on dedupe key).
package detection

import (
	"time"

	"github.com/google/uuid"
)

// Op is a predicate operator.
type Op string

const (
	OpEq       Op = "eq"       // string equals (case-insensitive)
	OpNeq      Op = "neq"      // not equals
	OpContains Op = "contains" // substring (case-insensitive)
	OpGte      Op = "gte"      // severity/confidence >=
	OpLte      Op = "lte"      // severity/confidence <=
	OpExists   Op = "exists"   // field present and non-empty
	OpRegex    Op = "regex"    // regular expression match
)

// Predicate tests one event field. Field is a normalized-event key
// (class_name, activity_name, severity, source, actor_ref, target_ref, action,
// outcome, confidence) or "data.<key>" for a payload field.
type Predicate struct {
	Field string `json:"field"`
	Op    Op     `json:"op"`
	Value string `json:"value"`
}

// Condition matches when ALL of All match AND at least one of Any matches
// (Any is optional). An empty condition never matches.
type Condition struct {
	All []Predicate `json:"all,omitempty"`
	Any []Predicate `json:"any,omitempty"`
}

// Rule is a detection rule (detection-as-code).
type Rule struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"` // nil = global
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`   // alert severity when it fires
	Confidence  int        `json:"confidence"` // 0-100
	MITRE       []string   `json:"mitre"`      // technique IDs
	Condition   Condition  `json:"condition"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Match is a rule firing against an event.
type Match struct {
	RuleID     uuid.UUID
	RuleName   string
	Severity   string
	Confidence int
	MITRE      []string
}

// SeverityRank orders severities for gte/lte comparisons.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "informational":
		return 1
	default:
		return 0
	}
}

// ValidSeverity reports whether s is a known severity.
func ValidSeverity(s string) bool { return SeverityRank(s) > 0 }
