package ingestion

// LAUNCH #1: the Entra identity mappers turn raw Graph telemetry into canonical events the stateful detection
// engine (DET-002) can predicate on. These are pure-function unit tests (no DB) — the value is proving a sign-in
// yields a user ACTOR + ip TARGET + success/failure OUTCOME, which is exactly what impossible-travel / MFA-fatigue
// detections need.

import "testing"

func TestNormalizeEntraSignIn(t *testing.T) {
	// A failed interactive sign-in from a foreign IP.
	in := Normalize(IngestInput{
		Source:   "microsoft-entra-signin",
		NativeID: "signin-1",
		Data: map[string]any{
			"userPrincipalName": "alice@corp.gov.gh",
			"ipAddress":         "203.0.113.9",
			"outcome_raw":       "failure",
			"countryOrRegion":   "RU",
			"mfaAuthMethod":     "PhoneAppNotification",
		},
	})
	if in.ClassName != "Authentication" {
		t.Errorf("class: got %q want Authentication", in.ClassName)
	}
	if in.ActorRef != "user:alice@corp.gov.gh" {
		t.Errorf("actor: got %q", in.ActorRef)
	}
	if in.TargetRef != "ip:203.0.113.9" {
		t.Errorf("target: got %q", in.TargetRef)
	}
	if in.Action != "signin" {
		t.Errorf("action: got %q", in.Action)
	}
	if in.Outcome != "failure" {
		t.Errorf("outcome: got %q want failure", in.Outcome)
	}
	if in.Severity != "low" { // failed auth = low signal
		t.Errorf("severity: got %q want low", in.Severity)
	}
	if in.Data["vendor"] != "Microsoft" || in.Data["product"] != "Entra ID" {
		t.Errorf("vendor/product: got %v/%v", in.Data["vendor"], in.Data["product"])
	}
	if in.Data["parser"] != "microsoft-entra-signin" {
		t.Errorf("parser stamp: got %v", in.Data["parser"])
	}
	// A successful sign-in is NOT elevated by the mapper; Normalize floors the empty severity to the baseline
	// "informational" (telemetry, not a signal on its own — only a FAILURE becomes "low" above).
	ok := Normalize(IngestInput{Source: "entra-signin", NativeID: "s2", Data: map[string]any{
		"userPrincipalName": "bob@corp.gov.gh", "ipAddress": "10.0.0.5", "outcome_raw": "success",
	}})
	if ok.Outcome != "success" || ok.Severity != "informational" {
		t.Errorf("success sign-in: outcome=%q severity=%q (want success/informational)", ok.Outcome, ok.Severity)
	}
}

func TestNormalizeEntraAudit(t *testing.T) {
	in := Normalize(IngestInput{
		Source:   "microsoft-entra-audit",
		NativeID: "audit-1",
		Data: map[string]any{
			"activityDisplayName": "Add member to role",
			"category":            "RoleManagement",
			"result":              "success",
			"initiatedByUpn":      "admin@corp.gov.gh",
			"targetUpn":           "victim@corp.gov.gh",
		},
	})
	if in.ClassName != "Directory Audit" {
		t.Errorf("class: got %q", in.ClassName)
	}
	if in.ActivityName != "Add member to role" {
		t.Errorf("activity: got %q", in.ActivityName)
	}
	if in.Action != "RoleManagement" {
		t.Errorf("action: got %q", in.Action)
	}
	if in.ActorRef != "user:admin@corp.gov.gh" {
		t.Errorf("actor: got %q", in.ActorRef)
	}
	if in.TargetRef != "user:victim@corp.gov.gh" {
		t.Errorf("target: got %q", in.TargetRef)
	}
	if in.Outcome != "success" {
		t.Errorf("outcome: got %q", in.Outcome)
	}
}

func TestNormalizeEntraRisky(t *testing.T) {
	in := Normalize(IngestInput{
		Source:   "microsoft-entra-risky",
		NativeID: "risky-1",
		Data: map[string]any{
			"userPrincipalName": "carol@corp.gov.gh",
			"riskLevel":         "high",
			"riskState":         "atRisk",
			"riskDetail":        "adminConfirmedUserCompromised",
		},
	})
	if in.ClassName != "Identity Risk" {
		t.Errorf("class: got %q", in.ClassName)
	}
	if in.ActorRef != "user:carol@corp.gov.gh" {
		t.Errorf("actor: got %q", in.ActorRef)
	}
	if in.Action != "risk_update" {
		t.Errorf("action: got %q", in.Action)
	}
	if in.Outcome != "atrisk" {
		t.Errorf("outcome: got %q want atrisk", in.Outcome)
	}
	if in.Severity != "high" { // high vendor risk → high signal
		t.Errorf("severity: got %q want high", in.Severity)
	}
}
