package detection

// Sigma rule import (SRS §6.6). The detection engine is not hard-wired to one rule
// language: Sigma rules are translated into the same Condition model the native
// engine evaluates, so customers can bring their own rules. This covers a practical
// subset of Sigma; unsupported constructs return a clear error rather than a wrong
// rule. YARA/CEL/custom-DSL importers can plug in the same way later.

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// sigmaDoc is the parsed Sigma YAML we consume.
type sigmaDoc struct {
	Title       string         `yaml:"title"`
	Description string         `yaml:"description"`
	Level       string         `yaml:"level"`
	Tags        []string       `yaml:"tags"`
	Detection   map[string]any `yaml:"detection"`
}

// canonicalFields are the normalized-event keys usable directly as predicate
// fields; anything else maps to data.<field>.
var canonicalFields = map[string]bool{
	"class_name": true, "activity_name": true, "severity": true, "source": true,
	"actor_ref": true, "target_ref": true, "action": true, "outcome": true, "confidence": true,
}

// ImportSigma translates a Sigma rule (YAML) into a detection CreateInput. It
// supports: one or more named selections combined with `and` (or a bare selection
// name) in the condition; field modifiers contains/startswith/endswith/re (plain =
// equals); list values (OR within a field). Unsupported: `or`/`not`/`N of` between
// selections, and more than one list-valued field (the Condition model expresses a
// single OR group). Those return an error.
func ImportSigma(data []byte) (CreateInput, error) {
	var doc sigmaDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return CreateInput{}, fmt.Errorf("sigma: invalid YAML: %w", err)
	}
	if strings.TrimSpace(doc.Title) == "" {
		return CreateInput{}, fmt.Errorf("sigma: title is required")
	}
	if doc.Detection == nil {
		return CreateInput{}, fmt.Errorf("sigma: detection block is required")
	}
	condRaw, ok := doc.Detection["condition"].(string)
	if !ok || strings.TrimSpace(condRaw) == "" {
		return CreateInput{}, fmt.Errorf("sigma: detection.condition is required and must be a string")
	}
	selNames, err := parseSigmaCondition(condRaw)
	if err != nil {
		return CreateInput{}, err
	}

	var cond Condition
	listUsed := false
	for _, name := range selNames {
		sel, ok := doc.Detection[name].(map[string]any)
		if !ok {
			return CreateInput{}, fmt.Errorf("sigma: selection %q not found or not a map", name)
		}
		all, anyPreds, err := translateSelection(sel)
		if err != nil {
			return CreateInput{}, err
		}
		cond.All = append(cond.All, all...)
		if len(anyPreds) > 0 {
			if listUsed {
				return CreateInput{}, fmt.Errorf("sigma: multiple list-valued fields are not supported (only one OR group)")
			}
			listUsed = true
			cond.Any = anyPreds
		}
	}
	if len(cond.All) == 0 && len(cond.Any) == 0 {
		return CreateInput{}, fmt.Errorf("sigma: no usable predicates produced")
	}

	sev := strings.ToLower(strings.TrimSpace(doc.Level))
	if !ValidSeverity(sev) {
		sev = "medium"
	}
	return CreateInput{
		Name:        doc.Title,
		Description: doc.Description,
		Severity:    sev,
		MITRE:       mitreFromTags(doc.Tags),
		Condition:   cond,
	}, nil
}

// parseSigmaCondition supports a bare selection name or `sel1 and sel2 and ...`.
// Anything else (or/not/parentheses/"1 of") is explicitly unsupported.
func parseSigmaCondition(c string) ([]string, error) {
	c = strings.TrimSpace(c)
	lower := strings.ToLower(c)
	if strings.Contains(lower, " or ") || strings.Contains(lower, "not ") ||
		strings.Contains(c, "(") || strings.Contains(lower, " of ") {
		return nil, fmt.Errorf("sigma: unsupported condition %q (only a selection or `x and y` is supported)", c)
	}
	parts := strings.Split(lower, " and ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("sigma: malformed condition %q", c)
		}
		out = append(out, p)
	}
	return out, nil
}

// translateSelection turns a Sigma selection map into predicates. Scalar values go
// to All (AND); a single list value's options go to Any (OR).
func translateSelection(sel map[string]any) (all, anyPreds []Predicate, err error) {
	for key, val := range sel {
		field, op, xform := parseFieldModifier(key)
		switch v := val.(type) {
		case string:
			all = append(all, Predicate{Field: field, Op: op, Value: xform(v)})
		case int:
			all = append(all, Predicate{Field: field, Op: op, Value: fmt.Sprintf("%d", v)})
		case float64:
			all = append(all, Predicate{Field: field, Op: op, Value: strings.TrimRight(fmt.Sprintf("%f", v), "0")})
		case bool:
			all = append(all, Predicate{Field: field, Op: op, Value: fmt.Sprintf("%t", v)})
		case []any:
			if len(anyPreds) > 0 {
				return nil, nil, fmt.Errorf("sigma: a selection may have at most one list-valued field")
			}
			for _, item := range v {
				anyPreds = append(anyPreds, Predicate{Field: field, Op: op, Value: xform(fmt.Sprintf("%v", item))})
			}
		default:
			return nil, nil, fmt.Errorf("sigma: unsupported value type for field %q", key)
		}
	}
	return all, anyPreds, nil
}

// parseFieldModifier splits "field|modifier" into a normalized-event field, an Op,
// and a value transform (for startswith/endswith which map onto regex anchors).
func parseFieldModifier(key string) (field string, op Op, xform func(string) string) {
	identity := func(s string) string { return s }
	parts := strings.SplitN(key, "|", 2)
	field = mapSigmaField(parts[0])
	if len(parts) == 1 {
		return field, OpEq, identity
	}
	switch strings.ToLower(parts[1]) {
	case "contains":
		return field, OpContains, identity
	case "re":
		return field, OpRegex, identity
	case "startswith":
		return field, OpRegex, func(s string) string { return "^" + regexp.QuoteMeta(s) }
	case "endswith":
		return field, OpRegex, func(s string) string { return regexp.QuoteMeta(s) + "$" }
	default:
		// Unknown modifier: fall back to equals on the base field.
		return field, OpEq, identity
	}
}

// mapSigmaField maps a Sigma field to a normalized-event key: canonical fields pass
// through (case-insensitively); everything else becomes data.<field> (vendor keys
// are preserved case-sensitively, since the normalized payload is case-sensitive).
func mapSigmaField(f string) string {
	if canonicalFields[strings.ToLower(f)] {
		return strings.ToLower(f)
	}
	return "data." + f
}

// mitreFromTags extracts ATT&CK technique ids from Sigma tags (e.g.
// "attack.t1059.001" -> "T1059.001").
func mitreFromTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "attack.t") {
			tech := strings.ToUpper(strings.TrimPrefix(lt, "attack."))
			out = append(out, tech)
		}
	}
	return out
}
