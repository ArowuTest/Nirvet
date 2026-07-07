package detection

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
)

// fieldValue resolves a normalized-event field (or data.<key>) to a string.
func fieldValue(ev eventstore.NormalizedEvent, field string) string {
	if strings.HasPrefix(field, "data.") {
		key := strings.TrimPrefix(field, "data.")
		if v, ok := ev.Data[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	switch field {
	case "class_name":
		return ev.ClassName
	case "activity_name":
		return ev.ActivityName
	case "severity":
		return ev.Severity
	case "source":
		return ev.Source
	case "actor_ref":
		return ev.ActorRef
	case "target_ref":
		return ev.TargetRef
	case "action":
		return ev.Action
	case "outcome":
		return ev.Outcome
	case "confidence":
		return strconv.Itoa(ev.Confidence)
	default:
		return ""
	}
}

func evalPredicate(ev eventstore.NormalizedEvent, p Predicate) bool {
	val := fieldValue(ev, p.Field)
	switch p.Op {
	case OpEq:
		return strings.EqualFold(val, p.Value)
	case OpNeq:
		return !strings.EqualFold(val, p.Value)
	case OpContains:
		return strings.Contains(strings.ToLower(val), strings.ToLower(p.Value))
	case OpExists:
		return val != ""
	case OpRegex:
		re, err := regexp.Compile(p.Value)
		return err == nil && re.MatchString(val)
	case OpGte, OpLte:
		return compareOrdered(p.Field, val, p.Value, p.Op)
	default:
		return false
	}
}

// compareOrdered handles severity (ranked) and numeric gte/lte.
func compareOrdered(field, val, want string, op Op) bool {
	var l, r int
	if field == "severity" {
		l, r = SeverityRank(val), SeverityRank(want)
		if r == 0 {
			return false
		}
	} else {
		var err error
		if l, err = strconv.Atoi(strings.TrimSpace(val)); err != nil {
			return false
		}
		if r, err = strconv.Atoi(strings.TrimSpace(want)); err != nil {
			return false
		}
	}
	if op == OpGte {
		return l >= r
	}
	return l <= r
}

// Matches reports whether the event satisfies the condition. An empty condition
// never matches (a rule must express at least one predicate).
func (c Condition) Matches(ev eventstore.NormalizedEvent) bool {
	if len(c.All) == 0 && len(c.Any) == 0 {
		return false
	}
	for _, p := range c.All {
		if !evalPredicate(ev, p) {
			return false
		}
	}
	if len(c.Any) > 0 {
		ok := false
		for _, p := range c.Any {
			if evalPredicate(ev, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
