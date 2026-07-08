package detection

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
)

// regexCache holds compiled regex-predicate patterns so the detection hot path does not
// recompile the same pattern on every event (R3 M1). Patterns are validated and warmed
// at rule-create time (validateCondition), so a miss here is the rare cold path. Keyed
// by pattern string; bounded by the number of distinct regex predicates across rules.
var regexCache sync.Map // map[string]*regexp.Regexp

// compileRegex returns a compiled pattern from the cache, compiling and storing it on
// first use. Returns the compile error for an invalid pattern (surfaced at create time).
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

// validateCondition rejects a condition whose regex predicates do not compile, so an
// invalid pattern is caught at rule-create time rather than silently never matching on
// the hot path (R3 L3). Accepted patterns are warmed into regexCache as a side effect.
func validateCondition(c Condition) error {
	check := func(ps []Predicate) error {
		for _, p := range ps {
			if p.Op == OpRegex {
				if _, err := compileRegex(p.Value); err != nil {
					return fmt.Errorf("invalid regex in predicate on %q: %w", p.Field, err)
				}
			}
		}
		return nil
	}
	if err := check(c.All); err != nil {
		return err
	}
	return check(c.Any)
}

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
		re, err := compileRegex(p.Value) // cached; recompiles only on a cold miss (R3 M1)
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
