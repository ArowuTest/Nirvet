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
