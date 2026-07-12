package ingestion

// Microsoft Entra ID identity-telemetry mappers (LAUNCH #1, US-029/US-030). These normalize the RAW identity
// streams the Graph poller now pulls (sign-ins, directory audits, risky-users) — NOT pre-formed Defender alerts —
// into canonical OCSF-inspired events so the stateful detection engine (DET-002) can evaluate MFA-fatigue /
// impossible-travel / risky-sign-in. The poller (connector/poller.go) ingests each stream item under a distinct
// source key with a flat Data map; these mappers set the canonical fields. Pure + defensively typed (never panic
// on a missing/odd field), mirroring the other vendor mappers.

import "strings"

func init() {
	RegisterMapper("microsoft-entra-signin", "microsoft-entra-signin", 1, normalizeEntraSignIn)
	RegisterMapper("entra-signin", "microsoft-entra-signin", 1, normalizeEntraSignIn)
	RegisterMapper("microsoft-entra-audit", "microsoft-entra-audit", 1, normalizeEntraAudit)
	RegisterMapper("entra-audit", "microsoft-entra-audit", 1, normalizeEntraAudit)
	RegisterMapper("microsoft-entra-risky", "microsoft-entra-risky", 1, normalizeEntraRisky)
	RegisterMapper("entra-risky", "microsoft-entra-risky", 1, normalizeEntraRisky)
}

// setEntraVendor stamps the canonical vendor/product (ADR-0006) so the mapper is self-contained (no sourceMeta
// entry needed) and analytics can group by vendor/product without re-parsing the source key.
func setEntraVendor(in *IngestInput, product string) {
	if _, ok := in.Data["vendor"]; !ok {
		in.Data["vendor"] = "Microsoft"
		in.Data["product"] = product
	}
}

// normalizeEntraSignIn maps an Entra sign-in log → OCSF Authentication (3002). Actor = the signing-in user,
// target = the source IP; result + MFA + location stay in Data so detection can predicate on them (impossible-
// travel needs user+ip+country; MFA-fatigue needs repeated user failures).
func normalizeEntraSignIn(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = "Authentication"
	}
	if _, ok := in.Data["class_uid"]; !ok {
		in.Data["class_uid"] = 3002
	}
	if in.ActorRef == "" {
		if upn := firstStr(in.Data, "userPrincipalName"); upn != "" {
			in.ActorRef = "user:" + upn
		}
	}
	if in.TargetRef == "" {
		if ip := firstStr(in.Data, "ipAddress"); ip != "" {
			in.TargetRef = "ip:" + ip
		}
	}
	if in.Action == "" {
		in.Action = "signin"
	}
	if in.Outcome == "" {
		// The poller pre-computes outcome_raw = "success"/"failure" from the sign-in status.errorCode (0 = ok).
		in.Outcome = strings.ToLower(firstStr(in.Data, "outcome_raw"))
	}
	// A failed interactive sign-in is at least a low-severity signal for detection (mirrors the Okta mapper).
	if in.Severity == "" && strings.EqualFold(in.Outcome, "failure") {
		in.Severity = "low"
	}
	setEntraVendor(in, "Entra ID")
}

// normalizeEntraAudit maps an Entra directory audit event → an account/config-change event. Actor = the
// initiator, target = the affected resource; the activity + result drive admin-change detections
// (e.g. privileged-role/key creation).
func normalizeEntraAudit(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = "Directory Audit"
	}
	if in.ActivityName == "" {
		in.ActivityName = firstStr(in.Data, "activityDisplayName")
	}
	if in.Action == "" {
		in.Action = firstStr(in.Data, "category", "activityDisplayName")
	}
	if in.ActorRef == "" {
		if upn := firstStr(in.Data, "initiatedByUpn"); upn != "" {
			in.ActorRef = "user:" + upn
		}
	}
	if in.TargetRef == "" {
		if tu := firstStr(in.Data, "targetUpn"); tu != "" {
			in.TargetRef = "user:" + tu
		} else if td := firstStr(in.Data, "targetDisplayName"); td != "" {
			in.TargetRef = "resource:" + td
		}
	}
	if in.Outcome == "" {
		in.Outcome = strings.ToLower(firstStr(in.Data, "result"))
	}
	if in.Severity == "" && strings.EqualFold(in.Outcome, "failure") {
		in.Severity = "low"
	}
	setEntraVendor(in, "Entra ID")
}

// normalizeEntraRisky maps an Entra Identity Protection risky-user record → an identity risk-signal event.
// Severity is derived from the vendor risk level so a high-risk user surfaces as a high-severity signal for
// correlation.
func normalizeEntraRisky(in *IngestInput) {
	if in.ClassName == "" {
		in.ClassName = "Identity Risk"
	}
	if in.ActivityName == "" {
		in.ActivityName = firstStr(in.Data, "riskDetail")
	}
	if in.Action == "" {
		in.Action = "risk_update"
	}
	if in.ActorRef == "" {
		if upn := firstStr(in.Data, "userPrincipalName"); upn != "" {
			in.ActorRef = "user:" + upn
		}
	}
	if in.Outcome == "" {
		in.Outcome = strings.ToLower(firstStr(in.Data, "riskState"))
	}
	if in.Severity == "" {
		switch strings.ToLower(firstStr(in.Data, "riskLevel")) {
		case "high":
			in.Severity = "high"
		case "medium":
			in.Severity = "medium"
		case "low":
			in.Severity = "low"
		}
	}
	setEntraVendor(in, "Entra ID")
}
