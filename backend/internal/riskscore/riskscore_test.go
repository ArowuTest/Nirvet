package riskscore

import "testing"

// zeroWeights returns the default config with all component weights overridable per test.
func cfgWith(exp, comp, op float64) Config {
	c := DefaultConfig()
	c.ExposureWeight, c.ComplianceWeight, c.OperationalWeight = exp, comp, op
	return c
}

func TestCompute_ZeroInputsAreLowRisk(t *testing.T) {
	s := Compute(DefaultConfig(), ExposureInput{BySeverity: map[string]int{}}, ComplianceInput{Present: false}, OperationalInput{})
	if s.Composite != 0 {
		t.Errorf("all-zero inputs: composite = %d, want 0", s.Composite)
	}
	if s.Band != "Low" {
		t.Errorf("all-zero inputs: band = %q, want Low", s.Band)
	}
}

func TestCompute_ComplianceIsInverseOfCoverage(t *testing.T) {
	// Only compliance weighted → composite == compliance risk == 100 - coverage.
	cfg := cfgWith(0, 1, 0)
	s := Compute(cfg, ExposureInput{BySeverity: map[string]int{}}, ComplianceInput{Present: true, AvgCoveragePct: 75}, OperationalInput{})
	if s.Composite != 25 {
		t.Errorf("coverage 75%% → composite = %d, want 25", s.Composite)
	}
}

func TestCompute_ComplianceAbsentIsExcludedAndRenormalized(t *testing.T) {
	// Equal weights, but compliance has no data. Composite must be the mean of exposure+operational ONLY —
	// the absent compliance weight must not dilute toward zero.
	cfg := cfgWith(1, 1, 1)
	withComp := Compute(cfg, ExposureInput{BySeverity: map[string]int{"critical": 3}}, ComplianceInput{Present: true, AvgCoveragePct: 100}, OperationalInput{OpenIncidents: 2})
	noComp := Compute(cfg, ExposureInput{BySeverity: map[string]int{"critical": 3}}, ComplianceInput{Present: false}, OperationalInput{OpenIncidents: 2})
	// With compliance present at 100% coverage (0 risk), it drags the composite DOWN. Excluding it should give a
	// HIGHER composite (mean over just the two non-zero components).
	if !(noComp.Composite > withComp.Composite) {
		t.Errorf("excluding a 0-risk compliance component should raise composite: withComp=%d noComp=%d", withComp.Composite, noComp.Composite)
	}
	// And the compliance component must be flagged not-present.
	for _, c := range noComp.Components {
		if c.Key == "compliance" && c.Present {
			t.Error("compliance component should be Present=false when no framework enabled")
		}
	}
}

func TestCompute_ExposureSaturatesAndIsMonotonic(t *testing.T) {
	cfg := cfgWith(1, 0, 0) // exposure only
	prev := -1
	for _, n := range []int{0, 1, 5, 20, 100, 1000} {
		s := Compute(cfg, ExposureInput{BySeverity: map[string]int{"critical": n}}, ComplianceInput{}, OperationalInput{})
		if s.Composite < prev {
			t.Errorf("exposure risk must be monotonic in vuln count: n=%d gave %d < prev %d", n, s.Composite, prev)
		}
		if s.Composite > 100 {
			t.Errorf("exposure risk must be bounded to 100: n=%d gave %d", n, s.Composite)
		}
		prev = s.Composite
	}
	// A large count must be near-saturated (well above half).
	big := Compute(cfg, ExposureInput{BySeverity: map[string]int{"critical": 1000}}, ComplianceInput{}, OperationalInput{})
	if big.Composite < 90 {
		t.Errorf("1000 open criticals should saturate exposure risk near 100, got %d", big.Composite)
	}
}

func TestCompute_ExploitedAndOverdueRaiseExposure(t *testing.T) {
	cfg := cfgWith(1, 0, 0)
	base := Compute(cfg, ExposureInput{BySeverity: map[string]int{"high": 2}}, ComplianceInput{}, OperationalInput{})
	worse := Compute(cfg, ExposureInput{BySeverity: map[string]int{"high": 2}, ExploitedOpen: 3, PastDue: 4}, ComplianceInput{}, OperationalInput{})
	if !(worse.Composite > base.Composite) {
		t.Errorf("exploited+overdue vulns must raise exposure: base=%d worse=%d", base.Composite, worse.Composite)
	}
}

func TestCompute_BandSelection(t *testing.T) {
	cfg := cfgWith(0, 1, 0) // drive composite purely from compliance so it's exact
	cases := []struct {
		coverage float64
		want     string
	}{
		{100, "Low"},     // risk 0
		{85, "Low"},      // risk 15
		{75, "Guarded"},  // risk 25
		{45, "Moderate"}, // risk 55
		{25, "Elevated"}, // risk 75
		{5, "High"},      // risk 95
	}
	for _, tc := range cases {
		s := Compute(cfg, ExposureInput{}, ComplianceInput{Present: true, AvgCoveragePct: tc.coverage}, OperationalInput{})
		if s.Band != tc.want {
			t.Errorf("coverage %.0f%% (risk %d) → band %q, want %q", tc.coverage, s.Composite, s.Band, tc.want)
		}
	}
}

func TestValidate_RejectsBadConfig(t *testing.T) {
	base := DefaultConfig()

	bad := base
	bad.ExposureWeight, bad.ComplianceWeight, bad.OperationalWeight = 0, 0, 0
	if bad.Validate() == nil {
		t.Error("all-zero weights should be rejected")
	}

	bad = base
	bad.Bands = []Band{{Max: 40, Label: "A", Tone: "ok"}, {Max: 20, Label: "B", Tone: "ok"}}
	if bad.Validate() == nil {
		t.Error("non-ascending bands should be rejected")
	}

	bad = base
	bad.Bands = []Band{{Max: 80, Label: "A", Tone: "ok"}}
	if bad.Validate() == nil {
		t.Error("top band < 100 should be rejected")
	}

	bad = base
	bad.Model.ExposureScale = 0
	if bad.Validate() == nil {
		t.Error("zero saturation scale should be rejected")
	}

	bad = base
	bad.Bands = []Band{{Max: 100, Label: "A", Tone: "purple"}}
	if bad.Validate() == nil {
		t.Error("invalid tone should be rejected")
	}

	if base.Validate() != nil {
		t.Error("the default config must be valid")
	}
}
