package detection

import (
	"testing"

	"github.com/google/uuid"
)

// TestRunCases_Native checks the test runner against a native Condition rule and the AllPass
// semantics the promotion gate relies on (empty suite is NOT all-pass).
func TestRunCases_Native(t *testing.T) {
	rule := &Rule{
		ID: uuid.New(), Severity: "high",
		Condition: Condition{All: []Predicate{{Field: "class_name", Op: OpContains, Value: "malware"}}},
	}
	cases := []TestCase{
		{Name: "hit", Sample: SampleEvent{ClassName: "Windows Malware Detected"}, ExpectedMatch: true},
		{Name: "miss", Sample: SampleEvent{ClassName: "benign login"}, ExpectedMatch: false},
	}
	run := runCases(rule, cases)
	if run.Total != 2 || run.Passed != 2 || run.Failed != 0 || !run.AllPass {
		t.Fatalf("expected 2/2 pass all-pass, got total=%d passed=%d failed=%d allpass=%v",
			run.Total, run.Passed, run.Failed, run.AllPass)
	}

	// A wrong expectation must be reported as a failure (and not all-pass).
	bad := runCases(rule, []TestCase{{Name: "wrong", Sample: SampleEvent{ClassName: "benign"}, ExpectedMatch: true}})
	if bad.Failed != 1 || bad.AllPass {
		t.Fatalf("expected 1 failure and not all-pass, got %+v", bad)
	}

	// An empty suite is not all-pass — the promotion gate must treat "no tests" as not promotable.
	empty := runCases(rule, nil)
	if empty.Total != 0 || empty.AllPass {
		t.Fatalf("empty suite must not be all-pass, got %+v", empty)
	}
}

// TestRunCases_CEL checks the runner exercises CEL expression rules via the same eval path.
func TestRunCases_CEL(t *testing.T) {
	rule := &Rule{ID: uuid.New(), Severity: "critical",
		Expression: `event.severity == "critical" && int(event.confidence) >= 80`}
	cases := []TestCase{
		{Name: "hit", Sample: SampleEvent{Severity: "critical", Confidence: 90}, ExpectedMatch: true},
		{Name: "low-conf", Sample: SampleEvent{Severity: "critical", Confidence: 10}, ExpectedMatch: false},
	}
	run := runCases(rule, cases)
	if !run.AllPass {
		t.Fatalf("CEL test cases should all pass, got %+v", run.Results)
	}
}

// TestStatsFrom checks FP-rate math and the min-sample gate on tuning recommendation.
func TestStatsFrom(t *testing.T) {
	rid := uuid.New()
	set := Settings{FPRateThreshold: 0.30, MinFeedbackSample: 20}

	// 10 FP of 40 = 0.25 < 0.30 → no recommendation even though sample is large enough.
	s := statsFrom(rid, map[Disposition]int{DispFalsePositive: 10, DispTruePositive: 30}, set)
	if s.Total != 40 || s.FPRate != 0.25 || s.TuningRecommended {
		t.Fatalf("expected total=40 rate=0.25 not-recommended, got %+v", s)
	}

	// 20 FP of 40 = 0.50 ≥ 0.30 with sample ≥ 20 → recommend.
	s2 := statsFrom(rid, map[Disposition]int{DispFalsePositive: 20, DispTruePositive: 20}, set)
	if !s2.TuningRecommended {
		t.Fatalf("expected tuning recommended, got %+v", s2)
	}

	// High rate but tiny sample (2 FP of 2) must NOT recommend — a lone FP shouldn't cry wolf.
	s3 := statsFrom(rid, map[Disposition]int{DispFalsePositive: 2}, set)
	if s3.FPRate != 1.0 || s3.TuningRecommended {
		t.Fatalf("small sample must not recommend, got %+v", s3)
	}
}

func TestDefaultSettings(t *testing.T) {
	d := DefaultSettings()
	if d.FPRateThreshold != 0.30 || d.MinFeedbackSample != 20 || d.CoverageWindowDays != 7 || !d.RequireTestsForProduction {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}
