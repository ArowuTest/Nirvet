package correlation

import (
	"testing"

	"github.com/google/uuid"
)

func TestExplain_FactorsSumMatchRiskScore(t *testing.T) {
	maxSev, count, techs, conf := "high", 3, 2, 80
	factors := Explain(maxSev, count, techs, conf)
	if len(factors) != 4 {
		t.Fatalf("expected 4 factors, got %d", len(factors))
	}
	sum := 0
	for _, f := range factors {
		sum += f.Contribution
	}
	// The clamped RiskScore is min(sum,100); with these inputs sum < 100 so they match exactly.
	if got := RiskScore(maxSev, count, techs, conf); got != sum {
		t.Fatalf("factor sum %d != RiskScore %d", sum, got)
	}
	// Severity is the dominant base factor.
	if factors[0].Name != "severity" || factors[0].Contribution != severityWeight("high") {
		t.Fatalf("severity factor wrong: %+v", factors[0])
	}
}

func TestEffectiveSeverityAndRisk(t *testing.T) {
	c := &Correlation{MaxSeverity: "medium", RiskScore: 40}
	if c.EffectiveSeverity() != "medium" || c.EffectiveRisk() != 40 {
		t.Fatal("with no override, effective == computed")
	}
	sev := "critical"
	risk := 95
	c.SeverityOverride, c.RiskOverride = &sev, &risk
	if c.EffectiveSeverity() != "critical" || c.EffectiveRisk() != 95 {
		t.Fatalf("override must win: %s/%d", c.EffectiveSeverity(), c.EffectiveRisk())
	}
	// An empty-string severity override is treated as no override.
	empty := ""
	c.SeverityOverride = &empty
	if c.EffectiveSeverity() != "medium" {
		t.Fatal("empty severity override should fall back to computed")
	}
	_ = uuid.Nil
}

func TestValidSeverity(t *testing.T) {
	for _, s := range []string{"informational", "low", "medium", "high", "critical"} {
		if !validSeverity(s) {
			t.Fatalf("%s should be valid", s)
		}
	}
	if validSeverity("severe") || validSeverity("") {
		t.Fatal("invalid severities must be rejected")
	}
}
