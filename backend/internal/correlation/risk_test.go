package correlation

import "testing"

func TestRiskScore_MonotonicAndBanded(t *testing.T) {
	// A single low-severity alert is low risk; a critical cluster with breadth is high.
	low := RiskScore("low", 1, 0, 0)
	crit := RiskScore("critical", 1, 0, 0)
	if !(low < crit) {
		t.Fatalf("critical (%d) should outrank low (%d)", crit, low)
	}
	// More alerts, more techniques, and higher confidence each raise the score.
	base := RiskScore("high", 1, 1, 0)
	if RiskScore("high", 5, 1, 0) <= base {
		t.Error("more alerts should raise risk")
	}
	if RiskScore("high", 1, 5, 0) <= base {
		t.Error("more distinct techniques should raise risk")
	}
	if RiskScore("high", 1, 1, 100) <= base {
		t.Error("higher confidence should raise risk")
	}
	// Bounded to 0..100.
	if got := RiskScore("critical", 100, 100, 100); got != 100 {
		t.Fatalf("risk must cap at 100, got %d", got)
	}
	// A busy critical cluster crosses the promote threshold.
	if RiskScore("critical", 3, 3, 80) < PromoteThreshold {
		t.Error("a busy critical cluster should be promote-worthy")
	}
}

func TestMergeTechniques_Dedupes(t *testing.T) {
	got := mergeTechniques([]string{"T1", "T2"}, []string{"T2", "T3", ""})
	if len(got) != 3 || got[0] != "T1" || got[2] != "T3" {
		t.Fatalf("merge wrong: %v", got)
	}
}

func TestWorseSeverity(t *testing.T) {
	if worseSeverity("low", "critical") != "critical" || worseSeverity("high", "medium") != "high" {
		t.Fatal("worseSeverity wrong")
	}
}
