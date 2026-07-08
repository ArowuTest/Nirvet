package severity

import "testing"

func TestRankOrdering(t *testing.T) {
	// The canonical §10.2 ordering must be strictly increasing informational..critical.
	order := []string{Informational, Low, Medium, High, Critical}
	for i := 1; i < len(order); i++ {
		if Rank(order[i]) <= Rank(order[i-1]) {
			t.Fatalf("expected %s to outrank %s (%d <= %d)", order[i], order[i-1], Rank(order[i]), Rank(order[i-1]))
		}
	}
}

func TestRankUnknownIsBelowEverything(t *testing.T) {
	// An unknown/blank severity must rank below every real one so it can never accidentally
	// outrank a genuine severity in a comparison (e.g. escalation matrix, max-severity).
	if Rank("") != -1 || Rank("bogus") != -1 {
		t.Fatalf("unknown/blank must rank -1, got %d/%d", Rank(""), Rank("bogus"))
	}
	if Rank("") >= Rank(Informational) {
		t.Fatalf("unknown must rank below informational")
	}
}

func TestValid(t *testing.T) {
	for _, s := range []string{Informational, Low, Medium, High, Critical} {
		if !Valid(s) {
			t.Fatalf("%s should be valid", s)
		}
	}
	for _, s := range []string{"", "p1", "CRITICAL"} {
		if Valid(s) {
			t.Fatalf("%q should be invalid", s)
		}
	}
}

func TestWorse(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{Low, Critical, Critical},
		{Critical, Low, Critical},
		{High, High, High},
		{"", Low, Low},       // any real severity beats unknown
		{Medium, "", Medium}, // unknown never wins
		{"", "", ""},         // two unknowns are stable
		{Informational, Low, Low},
	}
	for _, c := range cases {
		if got := Worse(c.a, c.b); got != c.want {
			t.Fatalf("Worse(%q,%q)=%q want %q", c.a, c.b, got, c.want)
		}
	}
}
