package detection

// §6.6 slice C entities + the pure evaluation used by the test runner (DET-005), the
// FP-feedback vocabulary (DET-007), coverage gaps (DET-009), and tenant tuning settings.

import (
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
)

// Disposition is an analyst's verdict on an alert, fed back to detection tuning (DET-007).
type Disposition string

const (
	DispTruePositive  Disposition = "true_positive"
	DispFalsePositive Disposition = "false_positive"
	DispBenign        Disposition = "benign"
	DispDuplicate     Disposition = "duplicate"
)

// ValidDisposition reports whether d is a known disposition.
func ValidDisposition(d Disposition) bool {
	switch d {
	case DispTruePositive, DispFalsePositive, DispBenign, DispDuplicate:
		return true
	}
	return false
}

// SampleEvent is a partial normalized event supplied as a detection test input (DET-005).
// It carries exactly the fields the evaluator reads; the runner materialises a
// NormalizedEvent from it so a test exercises the SAME matching path as live ingestion.
type SampleEvent struct {
	ClassName    string         `json:"class_name"`
	ActivityName string         `json:"activity_name"`
	Severity     string         `json:"severity"`
	Source       string         `json:"source"`
	ActorRef     string         `json:"actor_ref"`
	TargetRef    string         `json:"target_ref"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome"`
	Confidence   int            `json:"confidence"`
	Data         map[string]any `json:"data"`
}

// toEvent materialises the sample as a NormalizedEvent for evaluation.
func (s SampleEvent) toEvent() eventstore.NormalizedEvent {
	return eventstore.NormalizedEvent{
		ClassName: s.ClassName, ActivityName: s.ActivityName, Severity: s.Severity,
		Source: s.Source, ActorRef: s.ActorRef, TargetRef: s.TargetRef, Action: s.Action,
		Outcome: s.Outcome, Confidence: s.Confidence, Data: s.Data,
	}
}

// TestCase is a stored named sample + expected outcome for a rule (DET-005). SRS §9.4:
// every detection MUST carry test cases.
type TestCase struct {
	ID            uuid.UUID   `json:"id"`
	RuleID        uuid.UUID   `json:"rule_id"`
	Name          string      `json:"name"`
	Sample        SampleEvent `json:"sample"`
	ExpectedMatch bool        `json:"expected_match"`
	CreatedAt     string      `json:"created_at,omitempty"`
}

// TestResult is the outcome of running one test case against a rule.
type TestResult struct {
	Name          string `json:"name"`
	ExpectedMatch bool   `json:"expected_match"`
	ActualMatch   bool   `json:"actual_match"`
	Passed        bool   `json:"passed"`
}

// TestRun aggregates a rule's test results.
type TestRun struct {
	RuleID  uuid.UUID    `json:"rule_id"`
	Total   int          `json:"total"`
	Passed  int          `json:"passed"`
	Failed  int          `json:"failed"`
	AllPass bool         `json:"all_pass"`
	Results []TestResult `json:"results"`
}

// runCases evaluates a set of test cases against a rule and aggregates the run. M1: a CEL rule is
// compiled ONCE here (not per sample) — compiling per case turned a large sample array into thousands of
// CEL/RE2 compilations in one request. A compile error leaves prog nil → every case is a non-match, the
// same defensive-skip result the live engine produces.
func runCases(rule *Rule, cases []TestCase) TestRun {
	var prog cel.Program
	if rule.Expression != "" {
		if p, err := CompileCEL(rule.Expression); err == nil {
			prog = p
		}
	}
	eval := func(ev eventstore.NormalizedEvent) bool {
		if rule.Expression != "" {
			return prog != nil && EvalCEL(prog, ev)
		}
		return rule.Condition.Matches(ev)
	}
	run := TestRun{RuleID: rule.ID, Results: make([]TestResult, 0, len(cases))}
	for _, tc := range cases {
		actual := eval(tc.Sample.toEvent())
		passed := actual == tc.ExpectedMatch
		run.Results = append(run.Results, TestResult{
			Name: tc.Name, ExpectedMatch: tc.ExpectedMatch, ActualMatch: actual, Passed: passed,
		})
		run.Total++
		if passed {
			run.Passed++
		} else {
			run.Failed++
		}
	}
	// AllPass requires at least one case AND no failures — an empty suite is NOT "all pass"
	// (that distinction is what the promotion gate keys on: no tests ⇒ not promotable).
	run.AllPass = run.Total > 0 && run.Failed == 0
	return run
}

// FeedbackStats is per-rule disposition tuning data (DET-007).
type FeedbackStats struct {
	RuleID           uuid.UUID           `json:"rule_id"`
	Total            int                 `json:"total"`
	ByDisposition    map[Disposition]int `json:"by_disposition"`
	FalsePositives   int                 `json:"false_positives"`
	FPRate           float64             `json:"fp_rate"`
	TuningRecommended bool               `json:"tuning_recommended"`
}

// CoverageGap reports an active rule whose declared data-source dependencies are not being
// ingested for the tenant (DET-009) — the rule is live but can never fire.
type CoverageGap struct {
	RuleID      uuid.UUID `json:"rule_id"`
	Name        string    `json:"name"`
	Stage       string    `json:"stage"`
	MissingDeps []string  `json:"missing_deps"`
}

// Settings are the per-tenant detection tuning knobs (config-first, no hardcoding). Defaults
// mirror the DB column defaults so a tenant with no row still gets sane behaviour.
type Settings struct {
	FPRateThreshold           float64 `json:"fp_rate_threshold"`
	MinFeedbackSample         int     `json:"min_feedback_sample"`
	CoverageWindowDays        int     `json:"coverage_window_days"`
	RequireTestsForProduction bool    `json:"require_tests_for_production"`
}

// DefaultSettings are returned when a tenant has no detection_settings row.
func DefaultSettings() Settings {
	return Settings{FPRateThreshold: 0.30, MinFeedbackSample: 20, CoverageWindowDays: 7, RequireTestsForProduction: true}
}
