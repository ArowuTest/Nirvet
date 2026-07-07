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

func TestSeverityRank(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") {
		t.Fatal("critical must outrank high")
	}
	if SeverityRank("bogus") != 0 {
		t.Fatal("unknown severity ranks 0")
	}
}
