// Package detection is the detection-engineering engine (SRS §6.6; doc 04).
// Rules are condition-based (a portable subset of Sigma-style matching) with
// MITRE mapping and severity. Global rules (tenant_id NULL) apply to all tenants;
// tenants may add their own. The ingestion worker evaluates every new event
// against the catalogue and raises an alert per match (idempotent on dedupe key).
package detection

import (
	"strconv"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
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
	Expression  string     `json:"expression,omitempty"` // CEL; when set, takes precedence over Condition
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`

	// Detection-as-code lifecycle (SRS §9.4; DET-001/006). Stage gates whether the rule fires (only
	// pilot/production/tuned are active). Version increments on each promotion; OwnerID + declared
	// SourceDependencies are metadata.
	Stage              string     `json:"stage"`
	Version            int        `json:"version"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	SourceDependencies []string   `json:"source_dependencies"`

	// Stateful mode (DET-002). Kind defaults to KindSimple (single-event, the original behaviour). For
	// KindThreshold/KindDistinct the base Condition/Expression is the per-event CONTRIBUTION filter and the rule
	// fires once per (entity, window) when the count/distinct-count crosses Threshold. EntityField is the grouping
	// key (a normalized-event field, e.g. "actor_ref"); DistinctField (KindDistinct only) is the field whose
	// distinct values are counted (e.g. "data.countryOrRegion").
	Kind          string `json:"kind"`
	WindowSeconds int    `json:"window_seconds"`
	Threshold     int    `json:"threshold"`
	EntityField   string `json:"entity_field"`
	DistinctField string `json:"distinct_field"`
}

// Detection rule kinds (DET-002).
const (
	KindSimple    = "simple"    // single-event (default; original behaviour)
	KindThreshold = "threshold" // fire when >= Threshold contributing events for one entity in the window
	KindDistinct  = "distinct"  // fire when >= Threshold distinct DistinctField values for one entity in the window
)

// IsStateful reports whether the rule needs windowed state (threshold/distinct) rather than single-event eval.
func (r Rule) IsStateful() bool { return r.Kind == KindThreshold || r.Kind == KindDistinct }

// ValidateStateful checks a stateful rule's config is coherent + bounded (called at create). Simple rules pass.
// Threshold is bounded below the member cap so the flood backstop can never prevent a legitimate fire.
func (r Rule) ValidateStateful() error {
	if !r.IsStateful() {
		return nil
	}
	if r.WindowSeconds <= 0 || r.WindowSeconds > maxWindowSeconds {
		return httpx.ErrBadRequest("stateful rule: window_seconds must be between 1 and " + strconv.Itoa(maxWindowSeconds))
	}
	if r.Threshold <= 0 || r.Threshold > maxDistinctPerWindow {
		return httpx.ErrBadRequest("stateful rule: threshold must be between 1 and " + strconv.Itoa(maxDistinctPerWindow))
	}
	if r.EntityField == "" {
		return httpx.ErrBadRequest("stateful rule: entity_field is required")
	}
	if r.Kind == KindDistinct && r.DistinctField == "" {
		return httpx.ErrBadRequest("distinct rule: distinct_field is required")
	}
	return nil
}

// Detection lifecycle stages (SRS §9.4).
const (
	StageDraft      = "draft"
	StagePeerReview = "peer_review"
	StageQA         = "qa"
	StagePilot      = "pilot"
	StageProduction = "production"
	StageTuned      = "tuned"
	StageRetired    = "retired"
)

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
