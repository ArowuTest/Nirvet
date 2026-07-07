package ingestion

import "strings"

// Normalize applies source-specific mapping to bring vendor payloads into the
// canonical OCSF-inspired shape (doc 02 §4). New connectors add a case here; the
// rest of the pipeline (detection, correlation, AI) works off the canonical fields
// only. This is the "Normalization" stage of the end-to-end flow.
func Normalize(in IngestInput) IngestInput {
	in.Severity = normalizeSeverity(in.Severity)
	if in.Data == nil {
		in.Data = map[string]any{}
	}
	switch strings.ToLower(in.Source) {
	case "microsoft-defender", "defender":
		normalizeDefender(&in)
	case "microsoft-365", "m365":
		normalizeM365(&in)
	}
	return in
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

// normalizeSeverity coerces vendor severity casing to the canonical set.
func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "info", "informational":
		return "informational"
	case "low":
		return "low"
	case "medium", "moderate":
		return "medium"
	case "high":
		return "high"
	case "critical", "severe":
		return "critical"
	default:
		if s == "" {
			return "informational"
		}
		return s
	}
}
