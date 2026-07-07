package ingestion

import "testing"

// TestNormalizeDefender verifies vendor→canonical mapping fills empty canonical
// fields from a Microsoft Defender payload and normalizes severity casing.
func TestNormalizeDefender(t *testing.T) {
	in := IngestInput{
		Source:   "microsoft-defender",
		Severity: "High",
		Data: map[string]any{
			"title":           "Ransomware activity detected",
			"category":        "Ransomware",
			"deviceName":      "WIN-FIN-07",
			"accountName":     "jdoe",
			"mitreTechniques": []any{"T1486"},
		},
	}
	out := Normalize(in)

	if out.Severity != "high" {
		t.Errorf("severity = %q, want high", out.Severity)
	}
	if out.ClassName != "Ransomware" {
		t.Errorf("class_name = %q, want Ransomware", out.ClassName)
	}
	if out.TargetRef != "host:WIN-FIN-07" {
		t.Errorf("target_ref = %q, want host:WIN-FIN-07", out.TargetRef)
	}
	if out.ActorRef != "user:jdoe" {
		t.Errorf("actor_ref = %q, want user:jdoe", out.ActorRef)
	}
	if _, ok := out.Data["mitre"]; !ok {
		t.Error("expected mitre techniques surfaced to data.mitre")
	}
}

// TestNormalizeSeverity covers vendor severity casing/synonyms.
func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"High": "high", "INFORMATIONAL": "informational", "moderate": "medium",
		"severe": "critical", "": "informational", "low": "low",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNormalizeCrowdStrike maps a Falcon EDR detection incl. a 1-100 severity band.
func TestNormalizeCrowdStrike(t *testing.T) {
	out := Normalize(IngestInput{
		Source: "crowdstrike-falcon",
		Data: map[string]any{
			"detection_name": "SuspiciousProcess",
			"severity":       float64(85), // 1-100 → critical
			"device":         map[string]any{"hostname": "EC2-APP-1"},
			"user_name":      "svc-deploy",
			"technique_id":   "T1055",
		},
	})
	if out.Severity != "critical" {
		t.Errorf("severity = %q, want critical (score 85)", out.Severity)
	}
	if out.ClassName != "SuspiciousProcess" || out.TargetRef != "host:EC2-APP-1" || out.ActorRef != "user:svc-deploy" {
		t.Errorf("mapping wrong: class=%q target=%q actor=%q", out.ClassName, out.TargetRef, out.ActorRef)
	}
	if m, ok := out.Data["mitre"].([]string); !ok || len(m) != 1 || m[0] != "T1055" {
		t.Errorf("mitre not surfaced: %v", out.Data["mitre"])
	}
}

// TestNormalizeOkta maps a System Log event with nested actor/client/outcome.
func TestNormalizeOkta(t *testing.T) {
	out := Normalize(IngestInput{
		Source: "okta",
		Data: map[string]any{
			"eventType": "user.session.start",
			"actor":     map[string]any{"alternateId": "cfo@acme.com"},
			"client":    map[string]any{"ipAddress": "203.0.113.9"},
			"outcome":   map[string]any{"result": "FAILURE"},
		},
	})
	if out.ClassName != "user.session.start" || out.ActorRef != "user:cfo@acme.com" || out.TargetRef != "ip:203.0.113.9" {
		t.Errorf("mapping wrong: class=%q actor=%q target=%q", out.ClassName, out.ActorRef, out.TargetRef)
	}
	if out.Outcome != "failure" {
		t.Errorf("outcome = %q, want failure", out.Outcome)
	}
	if out.Severity != "low" {
		t.Errorf("failed auth should band to low, got %q", out.Severity)
	}
}

// TestNormalizePaloAlto maps a firewall threat log (named severity, src/dst IPs).
func TestNormalizePaloAlto(t *testing.T) {
	out := Normalize(IngestInput{
		Source: "palo-alto",
		Data: map[string]any{
			"threat_name": "Zeus C2", "severity": "Critical",
			"src": "10.0.0.5", "dst": "198.51.100.7", "action": "deny",
		},
	})
	if out.ClassName != "Zeus C2" || out.Severity != "critical" || out.ActorRef != "ip:10.0.0.5" || out.TargetRef != "ip:198.51.100.7" || out.Action != "deny" {
		t.Errorf("mapping wrong: %+v", out)
	}
}

// TestNormalizeGuardDuty maps a finding with a numeric 0.1-8.9 severity band.
func TestNormalizeGuardDuty(t *testing.T) {
	out := Normalize(IngestInput{
		Source: "aws-guardduty",
		Data: map[string]any{
			"type":     "UnauthorizedAccess:EC2/SSHBruteForce",
			"severity": float64(7.5), // >=7 → high
			"resource": map[string]any{"resourceType": "Instance"},
			"service":  map[string]any{"action": map[string]any{"actionType": "NETWORK_CONNECTION"}},
		},
	})
	if out.Severity != "high" {
		t.Errorf("severity = %q, want high (score 7.5)", out.Severity)
	}
	if out.ClassName != "UnauthorizedAccess:EC2/SSHBruteForce" || out.TargetRef != "resource:Instance" || out.Action != "network_connection" {
		t.Errorf("mapping wrong: class=%q target=%q action=%q", out.ClassName, out.TargetRef, out.Action)
	}
}

// TestSeverityBands checks the numeric-scale boundary mappings directly.
func TestSeverityBands(t *testing.T) {
	if severityFrom100(80) != "critical" || severityFrom100(79) != "high" || severityFrom100(19) != "informational" {
		t.Error("crowdstrike 1-100 banding wrong")
	}
	if severityFromGuardDuty(7.0) != "high" || severityFromGuardDuty(6.9) != "medium" || severityFromGuardDuty(0.05) != "informational" {
		t.Error("guardduty banding wrong")
	}
}

// TestUnknownSourceIsIdentity verifies an unregistered source passes through
// unchanged (except canonical severity) — the pipeline still accepts it.
func TestUnknownSourceIsIdentity(t *testing.T) {
	out := Normalize(IngestInput{Source: "some-new-siem", Severity: "High", ClassName: "raw"})
	if out.ClassName != "raw" || out.Severity != "high" {
		t.Errorf("unknown source should pass through: %+v", out)
	}
}

// TestNormalizePreservesExplicit verifies explicit canonical fields are not
// overwritten by vendor mapping.
func TestNormalizePreservesExplicit(t *testing.T) {
	in := IngestInput{
		Source:    "microsoft-defender",
		Severity:  "high",
		ClassName: "Explicit Class",
		TargetRef: "host:EXPLICIT",
		Data:      map[string]any{"category": "Ransomware", "deviceName": "OTHER"},
	}
	out := Normalize(in)
	if out.ClassName != "Explicit Class" || out.TargetRef != "host:EXPLICIT" {
		t.Fatalf("explicit fields overwritten: class=%q target=%q", out.ClassName, out.TargetRef)
	}
}
