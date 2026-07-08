package detection

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
)

func sampleEvent() eventstore.NormalizedEvent {
	return eventstore.NormalizedEvent{
		ClassName:  "Malware Detected",
		Severity:   "critical",
		Action:     "file_encrypt",
		ActorRef:   "user:jdoe",
		TargetRef:  "host:WIN-FIN-07",
		Confidence: 90,
	}
}

func TestConditionMatches(t *testing.T) {
	ev := sampleEvent()
	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"contains class", Condition{All: []Predicate{{"class_name", OpContains, "malware"}}}, true},
		{"contains class miss", Condition{All: []Predicate{{"class_name", OpContains, "phish"}}}, false},
		{"severity gte high", Condition{All: []Predicate{{"severity", OpGte, "high"}}}, true},
		{"severity gte critical", Condition{All: []Predicate{{"severity", OpGte, "critical"}}}, true},
		{"severity lte low", Condition{All: []Predicate{{"severity", OpLte, "low"}}}, false},
		{"action eq", Condition{Any: []Predicate{{"action", OpEq, "file_encrypt"}}}, true},
		{"confidence gte", Condition{All: []Predicate{{"confidence", OpGte, "80"}}}, true},
		{"confidence gte miss", Condition{All: []Predicate{{"confidence", OpGte, "99"}}}, false},
		{"regex actor", Condition{All: []Predicate{{"actor_ref", OpRegex, "^user:"}}}, true},
		{"all+any", Condition{
			All: []Predicate{{"severity", OpGte, "high"}},
			Any: []Predicate{{"action", OpEq, "file_encrypt"}, {"action", OpEq, "delete"}},
		}, true},
		{"all pass any fail", Condition{
			All: []Predicate{{"severity", OpGte, "high"}},
			Any: []Predicate{{"action", OpEq, "delete"}},
		}, false},
		{"empty never matches", Condition{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cond.Matches(ev); got != c.want {
				t.Fatalf("Matches = %v, want %v", got, c.want)
			}
		})
	}
}

// TestValidateCondition: an invalid regex predicate is rejected at validation time (so
// it never silently never-matches on the hot path), while valid predicates pass (R3 L3).
func TestValidateCondition(t *testing.T) {
	if err := validateCondition(Condition{All: []Predicate{{"actor_ref", OpRegex, "user:("}}}); err == nil {
		t.Fatal("an unclosed-group regex must be rejected at create time")
	}
	if err := validateCondition(Condition{Any: []Predicate{{"target_ref", OpRegex, "[a-z"}}}); err == nil {
		t.Fatal("an unterminated character class regex must be rejected")
	}
	// Valid patterns (and non-regex predicates) pass.
	if err := validateCondition(Condition{
		All: []Predicate{{"actor_ref", OpRegex, "^user:"}},
		Any: []Predicate{{"severity", OpGte, "high"}},
	}); err != nil {
		t.Fatalf("valid condition must pass validation: %v", err)
	}
}

// TestCompileRegexCache: the same pattern returns the same cached *Regexp instance (the
// hot path does not recompile), and an invalid pattern surfaces its error (R3 M1).
func TestCompileRegexCache(t *testing.T) {
	a, err := compileRegex(`^host:[0-9]+$`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	b, err := compileRegex(`^host:[0-9]+$`)
	if err != nil {
		t.Fatalf("compile (cached): %v", err)
	}
	if a != b {
		t.Fatal("identical pattern must return the cached compiled instance")
	}
	if _, err := compileRegex("("); err == nil {
		t.Fatal("invalid pattern must return a compile error")
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") {
		t.Fatal("critical must outrank high")
	}
	if SeverityRank("bogus") != 0 {
		t.Fatal("unknown severity ranks 0")
	}
}
