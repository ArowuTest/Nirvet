package ingestion

import (
	"fmt"
	"strings"
)

// Mapper brings one vendor's raw payload into the canonical OCSF-inspired shape
// (doc 02 §4). Mappers are pure and defensively typed — they never do I/O and
// never panic on a missing or oddly-typed field.
type Mapper func(*IngestInput)

// mapperInfo pairs a mapper with its identity: a stable parser name + an integer version
// (NORM-003). The version is bumped whenever a mapper's field logic changes, so a canonical
// event records exactly which parser build produced it and a schema-drift change is visible.
type mapperInfo struct {
	fn      Mapper
	name    string
	version int
}

// mappers is the source-normalizer registry. Every connector plugs into the SAME
// downstream pipeline (detection/correlation/AI work off canonical fields only),
// so adding a vendor is one mapper + a registry entry — no pipeline change.
var mappers = map[string]mapperInfo{}

// RegisterMapper adds (or overrides) a source mapper with its parser name + version. Sources are
// matched case-insensitively. Call from init or wiring; safe to alias multiple keys to one parser.
func RegisterMapper(source, name string, version int, m Mapper) {
	mappers[strings.ToLower(source)] = mapperInfo{fn: m, name: name, version: version}
}

func init() {
	RegisterMapper("microsoft-defender", "microsoft-defender", 1, normalizeDefender)
	RegisterMapper("defender", "microsoft-defender", 1, normalizeDefender)
	RegisterMapper("microsoft-365", "microsoft-365", 1, normalizeM365)
	RegisterMapper("m365", "microsoft-365", 1, normalizeM365)
	RegisterMapper("crowdstrike", "crowdstrike-falcon", 1, normalizeCrowdStrike)
	RegisterMapper("crowdstrike-falcon", "crowdstrike-falcon", 1, normalizeCrowdStrike)
	RegisterMapper("okta", "okta", 1, normalizeOkta)
	RegisterMapper("palo-alto", "palo-alto", 1, normalizePaloAlto)
	RegisterMapper("panw", "palo-alto", 1, normalizePaloAlto)
	RegisterMapper("aws-guardduty", "aws-guardduty", 1, normalizeGuardDuty)
	RegisterMapper("guardduty", "aws-guardduty", 1, normalizeGuardDuty)
	RegisterMapper("azure-sentinel", "azure-sentinel", 1, normalizeAzureSentinel)
	RegisterMapper("sentinel", "azure-sentinel", 1, normalizeAzureSentinel)
	RegisterMapper("gcp-scc", "gcp-scc", 1, normalizeGCPSCC)
	RegisterMapper("scc", "gcp-scc", 1, normalizeGCPSCC)
	// §6.5 #118 host telemetry from customer-deployed open agents (osquery/Wazuh) → OCSF classes + §6.5 field groups.
	RegisterMapper("host_osquery", "osquery", 1, normalizeOsquery)
	RegisterMapper("osquery", "osquery", 1, normalizeOsquery)
	RegisterMapper("host_wazuh", "wazuh", 1, normalizeWazuh)
	RegisterMapper("wazuh", "wazuh", 1, normalizeWazuh)
}

// sourceMeta records the vendor + product a source belongs to, stamped into the
// canonical event (ADR-0006) so analytics can group by vendor/product without
// re-parsing the source key. Sources not listed are stamped from the source key.
var sourceMeta = map[string][2]string{
	"microsoft-defender": {"Microsoft", "Defender"},
	"defender":           {"Microsoft", "Defender"},
	"microsoft-365":      {"Microsoft", "365"},
	"m365":               {"Microsoft", "365"},
	"crowdstrike":        {"CrowdStrike", "Falcon"},
	"crowdstrike-falcon": {"CrowdStrike", "Falcon"},
	"okta":               {"Okta", "Identity Cloud"},
	"palo-alto":          {"Palo Alto Networks", "NGFW"},
	"panw":               {"Palo Alto Networks", "NGFW"},
	"aws-guardduty":      {"AWS", "GuardDuty"},
	"guardduty":          {"AWS", "GuardDuty"},
	"azure-sentinel":     {"Microsoft", "Sentinel"},
	"sentinel":           {"Microsoft", "Sentinel"},
	"gcp-scc":            {"Google Cloud", "Security Command Center"},
	"scc":                {"Google Cloud", "Security Command Center"},
}

// Normalize applies the registered source mapper (identity fallback), canonicalises
// severity, and stamps vendor/product (ADR-0006). This is the "Normalization" stage
// of the end-to-end flow; everything downstream depends only on the canonical fields.
func Normalize(in IngestInput) IngestInput {
	if in.Data == nil {
		in.Data = map[string]any{}
	}
	parser, parserVersion := "identity", 0
	if mi, ok := mappers[strings.ToLower(in.Source)]; ok {
		mi.fn(&in) // may set a vendor severity (incl. numeric bands) into in.Severity
		parser, parserVersion = mi.name, mi.version
	}
	in.Severity = normalizeSeverity(in.Severity)
	// Canonical vendor/product (ADR-0006). Known sources get a friendly vendor +
	// product; unknown sources fall back to the source key so the fields are always
	// present for analytics.
	if _, ok := in.Data["vendor"]; !ok {
		if meta, known := sourceMeta[strings.ToLower(in.Source)]; known {
			in.Data["vendor"] = meta[0]
			in.Data["product"] = meta[1]
		} else if in.Source != "" {
			in.Data["vendor"] = in.Source
			in.Data["product"] = in.Source
		}
	}
	// NORM-003: record which parser (+version) produced this event and how completely it populated the
	// canonical fields, so a vendor schema change is observable, not silent. (This is a data-QUALITY /
	// drift signal — NOT NORM-006 inferred-vs-authoritative entity-resolution confidence, which is
	// deferred to §6.5 normalization slice B along with entity resolution.)
	in.Data["parser"] = parser
	in.Data["parser_version"] = parserVersion
	in.Data["normalization_confidence"] = NormalizationConfidence(in)
	return in
}

// NormalizationConfidence scores 0-100 how completely a mapper populated the canonical fields — a
// data-QUALITY / drift signal (NORM-003), NOT a detection weight and NOT NORM-006 resolution confidence.
// Weighted so the fields that matter most to downstream detection/correlation count more. class_name + a
// mapped entity are the backbone; a still-empty class_name (mapper fell through) is the strongest drift signal.
func NormalizationConfidence(in IngestInput) int {
	score, total := 0, 0
	add := func(weight int, present bool) {
		total += weight
		if present {
			score += weight
		}
	}
	add(30, in.ClassName != "")
	add(25, in.ActorRef != "" || in.TargetRef != "")
	add(15, in.Action != "")
	add(10, in.Outcome != "")
	add(10, in.ActivityName != "")
	_, hasMitre := in.Data["mitre"]
	add(10, hasMitre)
	if total == 0 {
		return 0
	}
	return score * 100 / total
}

// normalizeDefender maps a Microsoft Defender alert to canonical fields.
// Defender uses Title/Category/Severity(Informational..High) and an entities list.
func normalizeDefender(in *IngestInput) {
	if in.ClassName == "" {
		if c, ok := in.Data["category"].(string); ok && c != "" {
			in.ClassName = c
		} else if t, ok := in.Data["title"].(string); ok {
			in.ClassName = t
		}
	}
	// Defender exposes MITRE techniques; surface them for detection/enrichment.
	if tech, ok := in.Data["mitreTechniques"]; ok {
		in.Data["mitre"] = tech
	}
	// Map a device/host entity to the canonical target if not already set.
	if in.TargetRef == "" {
		if dev, ok := in.Data["deviceName"].(string); ok && dev != "" {
			in.TargetRef = "host:" + dev
		}
	}
	if in.ActorRef == "" {
		if u, ok := in.Data["accountName"].(string); ok && u != "" {
			in.ActorRef = "user:" + u
		}
	}
	if in.Action == "" {
		if a, ok := in.Data["category"].(string); ok {
			in.Action = strings.ToLower(strings.ReplaceAll(a, " ", "_"))
		}
	}
}

// normalizeM365 maps common Microsoft 365 audit fields.
func normalizeM365(in *IngestInput) {
	if in.ClassName == "" {
		if op, ok := in.Data["Operation"].(string); ok {
			in.ClassName = op
		}
	}
	if in.ActorRef == "" {
		if u, ok := in.Data["UserId"].(string); ok && u != "" {
			in.ActorRef = "user:" + u
		}
	}
}

// normalizeCrowdStrike maps a CrowdStrike Falcon EDR detection. Falcon carries a
// detection name, MITRE tactic/technique, a device/host, a user, and either a
// severity name or a 1-100 numeric score.
func normalizeCrowdStrike(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = firstStr(in.Data, "detection_name", "DetectName", "name")
	}
	if in.Severity == "" {
		if sev := firstStr(in.Data, "severity_name", "SeverityName"); sev != "" {
			in.Severity = sev
		} else if n, ok := firstNum(in.Data, "severity", "Severity", "max_severity"); ok {
			in.Severity = severityFrom100(n) // Falcon uses a 1-100 scale
		}
	}
	if in.TargetRef == "" {
		if h := firstStr(in.Data, "hostname", "ComputerName"); h != "" {
			in.TargetRef = "host:" + h
		} else if h := nestedStr(in.Data, "device", "hostname"); h != "" {
			in.TargetRef = "host:" + h
		}
	}
	if in.ActorRef == "" {
		if u := firstStr(in.Data, "user_name", "UserName"); u != "" {
			in.ActorRef = "user:" + u
		}
	}
	if tech := firstStr(in.Data, "technique_id", "technique"); tech != "" {
		in.Data["mitre"] = []string{tech}
	}
	if in.Action == "" {
		in.Action = "detection"
	}
}

// normalizeOkta maps an Okta System Log event: eventType, an actor (email),
// a client IP, and an outcome (SUCCESS/FAILURE).
func normalizeOkta(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = firstStr(in.Data, "eventType", "displayMessage")
	}
	if in.ActorRef == "" {
		if e := nestedStr(in.Data, "actor", "alternateId"); e != "" {
			in.ActorRef = "user:" + e
		}
	}
	if in.TargetRef == "" {
		if ip := nestedStr(in.Data, "client", "ipAddress"); ip != "" {
			in.TargetRef = "ip:" + ip
		}
	}
	if in.Outcome == "" {
		if r := nestedStr(in.Data, "outcome", "result"); r != "" {
			in.Outcome = strings.ToLower(r)
		}
	}
	if in.Action == "" {
		in.Action = firstStr(in.Data, "eventType")
	}
	// A failed auth is at least low-severity signal for detection.
	if in.Severity == "" && strings.EqualFold(nestedStr(in.Data, "outcome", "result"), "FAILURE") {
		in.Severity = "low"
	}
}

// normalizePaloAlto maps a Palo Alto Networks threat log: threat name, named
// severity, source/dest IPs, and a firewall action.
func normalizePaloAlto(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = firstStr(in.Data, "threat_name", "threatid", "threat")
	}
	if in.Severity == "" {
		in.Severity = firstStr(in.Data, "severity") // already named low..critical
	}
	if in.ActorRef == "" {
		if s := firstStr(in.Data, "src", "source_ip"); s != "" {
			in.ActorRef = "ip:" + s
		}
	}
	if in.TargetRef == "" {
		if d := firstStr(in.Data, "dst", "dest_ip"); d != "" {
			in.TargetRef = "ip:" + d
		}
	}
	if in.Action == "" {
		in.Action = firstStr(in.Data, "action") // allow|deny|drop|reset
	}
}

// normalizeGuardDuty maps an AWS GuardDuty finding: a finding type, a numeric
// severity (0.1-8.9), and a resource. Severity bands follow AWS guidance.
func normalizeGuardDuty(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = firstStr(in.Data, "type", "Type")
	}
	if in.Severity == "" {
		if n, ok := firstNum(in.Data, "severity", "Severity"); ok {
			in.Severity = severityFromGuardDuty(n)
		}
	}
	if in.TargetRef == "" {
		if rt := nestedStr(in.Data, "resource", "resourceType"); rt != "" {
			in.TargetRef = "resource:" + rt
		} else if rt := firstStr(in.Data, "resourceType"); rt != "" {
			in.TargetRef = "resource:" + rt
		}
	}
	if in.Action == "" {
		if at := nestedStr(in.Data, "service", "action", "actionType"); at != "" {
			in.Action = strings.ToLower(at)
		}
	}
}

// normalizeAzureSentinel maps a Microsoft Sentinel alert/incident: an alert name,
// a named severity, a compromised entity, and MITRE tactics/techniques.
func normalizeAzureSentinel(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = firstStr(in.Data, "AlertName", "Title", "title", "DisplayName")
	}
	if in.Severity == "" {
		in.Severity = firstStr(in.Data, "AlertSeverity", "severity", "Severity")
	}
	if in.TargetRef == "" {
		if e := firstStr(in.Data, "CompromisedEntity", "compromisedEntity"); e != "" {
			in.TargetRef = "host:" + e
		}
	}
	if tech := firstStr(in.Data, "Techniques", "technique", "TechniqueId"); tech != "" {
		in.Data["mitre"] = []string{tech}
	}
	if in.Action == "" {
		in.Action = firstStr(in.Data, "Tactics", "tactic")
	}
}

// normalizeGCPSCC maps a Google Security Command Center finding: a category, a
// named severity (CRITICAL..LOW), a resource, and a state.
func normalizeGCPSCC(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = firstStr(in.Data, "category", "Category")
	}
	if in.Severity == "" {
		in.Severity = firstStr(in.Data, "severity", "Severity") // CRITICAL/HIGH/... -> normalizeSeverity lowercases
	}
	if in.TargetRef == "" {
		if r := firstStr(in.Data, "resourceName", "resource_name"); r != "" {
			in.TargetRef = "resource:" + r
		}
	}
	if in.Outcome == "" {
		if st := firstStr(in.Data, "state", "State"); st != "" {
			in.Outcome = strings.ToLower(st)
		}
	}
}

// --- mapping helpers (pure, defensive) ---

// firstStr returns the first non-empty string value among the given keys.
func firstStr(data map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := data[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// firstNum returns the first numeric value among the given keys (handles the
// float64 JSON decodes to, plus int and numeric strings).
func firstNum(data map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		switch v := data[k].(type) {
		case float64:
			return v, true
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		case string:
			var f float64
			if _, err := fmt.Sscanf(v, "%g", &f); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

// nestedStr walks nested map[string]any by path and returns a string leaf.
func nestedStr(data map[string]any, path ...string) string {
	cur := any(data)
	for i, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
		if i == len(path)-1 {
			if s, ok := cur.(string); ok {
				return s
			}
			return ""
		}
	}
	return ""
}

// severityFrom100 bands a 1-100 vendor score (e.g. CrowdStrike) to the canonical set.
func severityFrom100(n float64) string {
	switch {
	case n >= 80:
		return "critical"
	case n >= 60:
		return "high"
	case n >= 40:
		return "medium"
	case n >= 20:
		return "low"
	default:
		return "informational"
	}
}

// severityFromGuardDuty bands a GuardDuty 0.1-8.9 score per AWS guidance.
func severityFromGuardDuty(n float64) string {
	switch {
	case n >= 7.0:
		return "high"
	case n >= 4.0:
		return "medium"
	case n >= 0.1:
		return "low"
	default:
		return "informational"
	}
}

// normalizeSeverity maps a vendor severity to the canonical set (§10.2). It is CANONICAL-GUARANTEED: the
// return value is always one of informational|low|medium|high|critical, so a non-standard vendor value
// (e.g. "warning", "SEVERITY_UNSPECIFIED", a numeric level) can never reach the events CHECK constraint
// and dead-letter a legitimate event (R6-C1). An unrecognized non-empty value coerces to informational
// (fail-safe: keep the event, do not silently drop it) — the worker logs the coercion.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "informational", "info", "information", "notice", "debug", "trace", "0", "1":
		return "informational"
	case "low", "2":
		return "low"
	case "medium", "moderate", "warning", "warn", "3":
		return "medium"
	case "high", "error", "err", "4":
		return "high"
	case "critical", "severe", "crit", "fatal", "emergency", "alert", "5":
		return "critical"
	default:
		// Unknown or empty → the safe canonical floor. Never returns a non-canonical value.
		return "informational"
	}
}

// canonicalSeverities is the DB-enforced set; isCanonicalSeverity guards the worker's pre-Append clamp.
var canonicalSeverities = map[string]bool{
	"informational": true, "low": true, "medium": true, "high": true, "critical": true,
}

func isCanonicalSeverity(s string) bool { return canonicalSeverities[s] }
