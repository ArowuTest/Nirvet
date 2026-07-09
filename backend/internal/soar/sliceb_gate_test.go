package soar

import "testing"

// TestEvaluateGate_Precedence proves the safety-gate precedence and MUST-4 (every non-live outcome has a
// reason). Each case flips exactly the dominating input to show it wins over the ones below it.
func TestEvaluateGate_Precedence(t *testing.T) {
	// A baseline that would otherwise go live.
	base := gateInputs{tenantEnabled: true, canAuto: true, rateRemaining: 5}

	cases := []struct {
		name string
		in   gateInputs
		want gateOutcome
	}{
		{"live baseline", base, gateLive},
		{"kill-switch dominates everything", gateInputs{killSwitch: true, tenantEnabled: true, canAuto: true, rateRemaining: 5, tenantDryRun: true}, gateWithhold},
		{"disabled (no dry-run) withholds", gateInputs{tenantEnabled: false, canAuto: true, rateRemaining: 5}, gateWithhold},
		{"dry-run satisfies enablement", gateInputs{tenantEnabled: false, tenantDryRun: true, canAuto: true, rateRemaining: 5}, gateDryRun},
		{"not-auto forces manual (over rate/dry-run)", gateInputs{tenantEnabled: true, tenantDryRun: true, canAuto: false, canAutoReason: "x", rateRemaining: 0}, gateManual},
		{"rate exhausted withholds", gateInputs{tenantEnabled: true, canAuto: true, rateRemaining: 0}, gateWithhold},
		{"tenant dry-run", gateInputs{tenantEnabled: true, tenantDryRun: true, canAuto: true, rateRemaining: 5}, gateDryRun},
		{"platform dry-run", gateInputs{tenantEnabled: true, platformDryRun: true, canAuto: true, rateRemaining: 5}, gateDryRun},
	}
	for _, c := range cases {
		got, reason := evaluateGate(c.in)
		if got != c.want {
			t.Errorf("%s: got outcome %d want %d (reason %q)", c.name, got, c.want, reason)
		}
		if got != gateLive && reason == "" {
			t.Errorf("%s: non-live outcome must carry a reason (MUST-4)", c.name)
		}
	}
}

func TestRateCapFor(t *testing.T) {
	s := SoarSettings{MaxClass3PerHour: 7, MaxClass4PerHour: 0}
	if s.rateCapFor(RiskHigh) != 7 {
		t.Fatalf("class3 cap want 7, got %d", s.rateCapFor(RiskHigh))
	}
	if s.rateCapFor(RiskBusinessCritical) != 0 {
		t.Fatalf("class4 cap want 0, got %d", s.rateCapFor(RiskBusinessCritical))
	}
	if s.rateCapFor(RiskLow) < 1000 {
		t.Fatalf("low class must be effectively uncapped by the destructive limiter")
	}
}
