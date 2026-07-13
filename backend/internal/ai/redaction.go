package ai

// §6.12 #188 HEAVY-1 — the AI-egress Redactor. This is the control that keeps raw customer telemetry
// (usernames, emails, IPs, hostnames, tokens, jurisdictional IDs) from leaving the sovereign platform to a
// third-party LLM. It is applied at the SINGLE egress chokepoint (Service.completeExternal) — no AI feature can
// reach a provider without passing through it (CI-fenced), so masking is safe-by-construction, not opt-in.
//
// Design (reviewer pre-code pass, Jul 12):
//   - Field-aware. Each fenced line is `key=value`. SAFE keys (severity/status/mitre…) pass VERBATIM so redaction
//     can never silently over-mask and break grounding. IDENTIFIER keys (actor/target/source/asset refs) are
//     high re-identification value and are wholesale-masked from `balanced` up. FREE-TEXT keys (title/incident)
//     are token-masked in `balanced` and wholesale-masked in `strict`.
//   - Grounding-preserving. Masking uses STABLE PER-CALL placeholders (EMAIL_1, IP_1, IDENT_1): the same raw value
//     maps to the same placeholder within one request, so the model still correlates "actor X did A then X did B".
//   - No durable pseudonym. The value→placeholder map lives only for the call, in memory — it is NEVER persisted
//     or logged (a durable map would itself be a re-identification key = new PII surface).
//   - Mask-by-default / fail-safe. `balanced` is the shipped default; a missing/broken policy resolves to
//     balanced (mask), never cleartext. `off` is an explicit, audited tenant choice.

import (
	"regexp"
	"strconv"
	"strings"
)

// Redaction modes (source of truth for the ai_redaction_policy.mode CHECK).
const (
	RedactBalanced = "balanced" // mask PII/secret tokens everywhere + wholesale-mask identifier fields
	RedactStrict   = "strict"   // balanced + also wholesale-mask free-text fields (title/incident)
	RedactOff      = "off"      // no masking (explicit, audited tenant choice)
)

// RedactionPolicy is the resolved per-tenant policy (own row else global default).
type RedactionPolicy struct {
	Enabled bool
	Mode    string
}

// defaultRedactionPolicy is the fail-safe used when no policy is wired or config load/parse fails: mask-by-default,
// balanced. A broken config NEVER egresses cleartext.
func defaultRedactionPolicy() RedactionPolicy {
	return RedactionPolicy{Enabled: true, Mode: RedactBalanced}
}

// CompiledPattern is one masking rule: a compiled RE2 regex and the placeholder prefix its matches collapse to.
type CompiledPattern struct {
	Placeholder string
	Re          *regexp.Regexp
}

// Built-in compiled floor — always active (never disable-able), so masking works even with zero DB config. Split
// into "specific" (anchored token shapes) and "broad" (greedy digit/entropy runs); the service composes the final
// order as specific ++ custom(jurisdictional) ++ broad so a precise pattern (e.g. Ghana Card) wins over the greedy
// phone/secret sweeps.
var (
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reIPv4   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	reIPv6   = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b`)
	rePhone  = regexp.MustCompile(`\+?[0-9][0-9().\-\s]{6,}[0-9]`)
	reSecret = regexp.MustCompile(`\b[A-Za-z0-9+/=_\-]{24,}\b`)
)

// builtinSpecific / builtinBroad are the always-on floor patterns.
func builtinSpecific() []CompiledPattern {
	return []CompiledPattern{
		{Placeholder: "EMAIL", Re: reEmail},
		{Placeholder: "IP", Re: reIPv4},
		{Placeholder: "IP", Re: reIPv6},
	}
}
func builtinBroad() []CompiledPattern {
	return []CompiledPattern{
		{Placeholder: "PHONE", Re: rePhone},
		{Placeholder: "SECRET", Re: reSecret},
	}
}

// fieldClass is the redaction class of a fenced field key.
type fieldClass uint8

const (
	classFreeText   fieldClass = iota // token-mask in balanced; wholesale in strict (default for unknown keys)
	classSafe                         // never masked (enumerated, low-PII structural fields)
	classIdentifier                   // wholesale-masked from balanced up (usernames/hostnames/resource ids)
)

// safeKeys / identifierKeys classify the field keys the AI egress builders emit (SummariseAlert evidence +
// TriageIncident triageFacts). Unknown keys default to free-text (still token-masked) — a new sensitive field
// should be classified deliberately here, not rely on the default.
var (
	safeKeys = map[string]bool{
		"severity": true, "status": true, "stage": true, "sla": true, "mitre": true,
		"alerts": true, "confidence": true, "criticality": true, "asset_criticalities": true,
	}
	identifierKeys = map[string]bool{
		"actor": true, "target": true, "source": true, "asset": true, "entity": true,
		"affected_assets": true, "affected_asset_refs": true,
	}
)

func classify(key string) fieldClass {
	switch {
	case safeKeys[key]:
		return classSafe
	case identifierKeys[key]:
		return classIdentifier
	default:
		return classFreeText
	}
}

// allocator hands out stable per-call placeholders. Not exported, not persisted, discarded when the call returns.
type allocator struct {
	seen  map[string]string // (prefix\x00raw) → placeholder
	next  map[string]int    // prefix → next ordinal
	count int               // total substitutions (for audit; the VALUES are never recorded)
}

func newAllocator() *allocator {
	return &allocator{seen: map[string]string{}, next: map[string]int{}}
}

// placeholder returns the stable placeholder for (prefix, raw), minting a new ordinal on first sight.
func (a *allocator) placeholder(prefix, raw string) string {
	k := prefix + "\x00" + raw
	if p, ok := a.seen[k]; ok {
		return p
	}
	a.next[prefix]++
	p := prefix + "_" + strconv.Itoa(a.next[prefix])
	a.seen[k] = p
	a.count++
	return p
}

// tokenMask replaces every pattern match in val with a stable placeholder. Patterns run in the given order so a
// specific jurisdictional pattern (placed before the broad phone/secret sweeps) wins.
func (a *allocator) tokenMask(val string, patterns []CompiledPattern) string {
	for _, p := range patterns {
		pat := p
		val = pat.Re.ReplaceAllStringFunc(val, func(m string) string {
			return a.placeholder(pat.Placeholder, m)
		})
	}
	return val
}

// redactLines applies the policy to the fenced lines, returning the redacted lines and an audit-only result
// (applied?, mode, substitution count — never the cleartext or the map). `patterns` is the composed, ordered set
// (specific ++ custom ++ broad) supplied by the caller.
func redactLines(lines []string, policy RedactionPolicy, patterns []CompiledPattern) ([]string, RedactionResult) {
	if !policy.Enabled || policy.Mode == RedactOff {
		return lines, RedactionResult{Applied: false, Mode: policy.Mode}
	}
	strict := policy.Mode == RedactStrict
	alloc := newAllocator()
	out := make([]string, len(lines))
	for i, ln := range lines {
		key, val, hasKey := "", ln, false
		if eq := strings.IndexByte(ln, '='); eq >= 0 {
			key, val, hasKey = ln[:eq], ln[eq+1:], true
		}
		red := redactValue(key, val, hasKey, strict, patterns, alloc)
		if hasKey {
			out[i] = key + "=" + red
		} else {
			out[i] = red
		}
	}
	mode := RedactBalanced
	if strict {
		mode = RedactStrict
	}
	return out, RedactionResult{Applied: true, Mode: mode, Count: alloc.count}
}

// redactValue applies the class rule to one field value.
func redactValue(key, val string, hasKey, strict bool, patterns []CompiledPattern, alloc *allocator) string {
	if val == "" {
		return val
	}
	class := classFreeText
	if hasKey {
		class = classify(key)
	}
	switch class {
	case classSafe:
		return val // never masked — verbatim (grounding + no over-mask)
	case classIdentifier:
		// The whole value IS a structured identifier (username/hostname/resource id) → collapse it, stable per call.
		return alloc.placeholder("IDENT", val)
	default: // classFreeText
		if strict {
			return alloc.placeholder("TEXT", val) // strict: wholesale-mask free text too
		}
		return alloc.tokenMask(val, patterns) // balanced: mask PII/secret tokens, keep the rest as analytic signal
	}
}

// RedactionResult is the audit-only outcome of a redaction pass. It NEVER carries cleartext or the placeholder map.
type RedactionResult struct {
	Applied bool
	Mode    string
	Count   int
}
