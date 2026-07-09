package detection

// §6.6 slice C service: test-against-sample (DET-005), FP-disposition feedback + tuning stats
// (DET-007), data-source coverage gaps (DET-009), and per-tenant settings. Assistive: stats and
// coverage are surfaced for the detection engineer, never auto-acted.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// AddTestCaseInput adds a test case to a rule (DET-005).
type AddTestCaseInput struct {
	Name          string      `json:"name"`
	Sample        SampleEvent `json:"sample"`
	ExpectedMatch bool        `json:"expected_match"`
}

// AddTestCase stores a named test case for a rule the tenant can see.
func (s *Service) AddTestCase(ctx context.Context, tenantID, ruleID uuid.UUID, in AddTestCaseInput, by uuid.UUID) (*TestCase, error) {
	if in.Name == "" {
		return nil, httpx.ErrBadRequest("test case name is required")
	}
	rule, err := s.repo.GetRule(ctx, tenantID, ruleID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load rule")
	}
	if rule == nil {
		return nil, httpx.ErrNotFound("rule not found")
	}
	tc := &TestCase{ID: uuid.New(), RuleID: ruleID, Name: in.Name, Sample: in.Sample, ExpectedMatch: in.ExpectedMatch}
	if err := s.repo.AddTestCase(ctx, tenantID, tc, by); err != nil {
		return nil, httpx.ErrInternal("could not store test case")
	}
	return tc, nil
}

// ListTestCases returns a rule's stored test cases.
func (s *Service) ListTestCases(ctx context.Context, tenantID, ruleID uuid.UUID) ([]TestCase, error) {
	return s.repo.ListTestCases(ctx, tenantID, ruleID)
}

// DeleteTestCase removes a test case.
func (s *Service) DeleteTestCase(ctx context.Context, tenantID, id uuid.UUID) error {
	applied, err := s.repo.DeleteTestCase(ctx, tenantID, id)
	if err != nil {
		return httpx.ErrInternal("could not delete test case")
	}
	if !applied {
		return httpx.ErrNotFound("test case not found")
	}
	return nil
}

// RunTests evaluates a rule against its stored test cases (DET-005).
func (s *Service) RunTests(ctx context.Context, tenantID, ruleID uuid.UUID) (*TestRun, error) {
	rule, err := s.repo.GetRule(ctx, tenantID, ruleID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load rule")
	}
	if rule == nil {
		return nil, httpx.ErrNotFound("rule not found")
	}
	cases, err := s.repo.ListTestCases(ctx, tenantID, ruleID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load test cases")
	}
	run := runCases(rule, cases)
	return &run, nil
}

// RunSamples evaluates a saved rule against inline samples (ad-hoc authoring — nothing persisted).
func (s *Service) RunSamples(ctx context.Context, tenantID, ruleID uuid.UUID, cases []TestCase) (*TestRun, error) {
	rule, err := s.repo.GetRule(ctx, tenantID, ruleID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load rule")
	}
	if rule == nil {
		return nil, httpx.ErrNotFound("rule not found")
	}
	run := runCases(rule, cases)
	return &run, nil
}

// RecordDetectionFeedback appends disposition feedback attributed to a rule (DET-007). It satisfies
// alert.FeedbackSink — the alert module calls this when an analyst dispositions an alert, keeping
// alert decoupled from detection. disposition is validated here (defense-in-depth).
func (s *Service) RecordDetectionFeedback(ctx context.Context, tenantID, ruleID, alertID uuid.UUID, disposition, reason string, by uuid.UUID) error {
	d := Disposition(disposition)
	if !ValidDisposition(d) {
		return httpx.ErrBadRequest("invalid disposition")
	}
	var aptr *uuid.UUID
	if alertID != uuid.Nil {
		aptr = &alertID
	}
	if err := s.repo.RecordFeedback(ctx, tenantID, ruleID, aptr, d, reason, by); err != nil {
		return httpx.ErrInternal("could not record feedback")
	}
	return nil
}

// RuleFeedbackStats returns per-disposition counts + FP rate for a rule (DET-007).
func (s *Service) RuleFeedbackStats(ctx context.Context, tenantID, ruleID uuid.UUID) (*FeedbackStats, error) {
	counts, err := s.repo.FeedbackCounts(ctx, tenantID, ruleID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load feedback")
	}
	set, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load settings")
	}
	return statsFrom(ruleID, counts, set), nil
}

// statsFrom computes FP rate + tuning recommendation from raw counts and settings.
func statsFrom(ruleID uuid.UUID, counts map[Disposition]int, set Settings) *FeedbackStats {
	total := 0
	for _, n := range counts {
		total += n
	}
	fp := counts[DispFalsePositive]
	rate := 0.0
	if total > 0 {
		rate = float64(fp) / float64(total)
	}
	// Only recommend tuning once the sample is large enough that the rate is meaningful — a lone
	// false positive on a fresh rule shouldn't flag it (min_feedback_sample, config).
	recommend := total >= set.MinFeedbackSample && rate >= set.FPRateThreshold
	return &FeedbackStats{
		RuleID: ruleID, Total: total, ByDisposition: counts,
		FalsePositives: fp, FPRate: rate, TuningRecommended: recommend,
	}
}

// TuningView lists rules whose FP rate crosses the configured threshold with a sufficient sample
// (DET-007) — the "these detections need tuning" queue.
func (s *Service) TuningView(ctx context.Context, tenantID uuid.UUID) ([]FeedbackStats, error) {
	rows, err := s.repo.FeedbackByRule(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load feedback")
	}
	set, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load settings")
	}
	byRule := map[uuid.UUID]map[Disposition]int{}
	for _, rd := range rows {
		if byRule[rd.RuleID] == nil {
			byRule[rd.RuleID] = map[Disposition]int{}
		}
		byRule[rd.RuleID][rd.Disp] = rd.Count
	}
	out := []FeedbackStats{}
	for rid, counts := range byRule {
		st := statsFrom(rid, counts, set)
		if st.TuningRecommended {
			out = append(out, *st)
		}
	}
	return out, nil
}

// CoverageGaps reports active rules whose declared data-source dependencies are not being ingested
// for the tenant within the configured window (DET-009).
func (s *Service) CoverageGaps(ctx context.Context, tenantID uuid.UUID) ([]CoverageGap, error) {
	set, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load settings")
	}
	rules, err := s.repo.ListActive(ctx, tenantID)
	if err != nil {
		return nil, httpx.ErrInternal("could not load rules")
	}
	sources, err := s.repo.RecentSources(ctx, tenantID, set.CoverageWindowDays)
	if err != nil {
		return nil, httpx.ErrInternal("could not load ingested sources")
	}
	gaps := []CoverageGap{}
	for _, r := range rules {
		if len(r.SourceDependencies) == 0 {
			continue
		}
		var missing []string
		for _, dep := range r.SourceDependencies {
			if !sources[dep] {
				missing = append(missing, dep)
			}
		}
		if len(missing) > 0 {
			gaps = append(gaps, CoverageGap{RuleID: r.ID, Name: r.Name, Stage: r.Stage, MissingDeps: missing})
		}
	}
	return gaps, nil
}

// Settings returns the tenant's detection settings (defaults if unset).
func (s *Service) Settings(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	set, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return Settings{}, httpx.ErrInternal("could not load settings")
	}
	return set, nil
}

// SetSettings validates and upserts the tenant's detection settings.
func (s *Service) SetSettings(ctx context.Context, tenantID uuid.UUID, in Settings) (Settings, error) {
	if in.FPRateThreshold < 0 || in.FPRateThreshold > 1 {
		return Settings{}, httpx.ErrBadRequest("fp_rate_threshold must be between 0 and 1")
	}
	if in.MinFeedbackSample < 1 {
		return Settings{}, httpx.ErrBadRequest("min_feedback_sample must be >= 1")
	}
	if in.CoverageWindowDays < 1 || in.CoverageWindowDays > 90 {
		return Settings{}, httpx.ErrBadRequest("coverage_window_days must be between 1 and 90")
	}
	if err := s.repo.SetSettings(ctx, tenantID, in); err != nil {
		return Settings{}, httpx.ErrInternal("could not save settings")
	}
	return in, nil
}

// promotable reports whether a rule may be promoted to production under the tenant's test policy
// (DET-005 promotion gate). When require_tests_for_production is on, the rule must have ≥1 test case
// and all must pass. Returns a reason when not promotable.
func (s *Service) promotable(ctx context.Context, tenantID, ruleID uuid.UUID) (ok bool, reason string, err error) {
	set, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return false, "", err
	}
	if !set.RequireTestsForProduction {
		return true, "", nil
	}
	rule, err := s.repo.GetRule(ctx, tenantID, ruleID)
	if err != nil {
		return false, "", err
	}
	if rule == nil {
		return false, "rule not found", nil
	}
	cases, err := s.repo.ListTestCases(ctx, tenantID, ruleID)
	if err != nil {
		return false, "", err
	}
	run := runCases(rule, cases)
	if run.Total == 0 {
		return false, "rule has no test cases; add and pass tests before promoting to production", nil
	}
	if !run.AllPass {
		return false, "rule has failing test cases; all tests must pass before promotion to production", nil
	}
	return true, "", nil
}
