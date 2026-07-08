package detection

import (
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
)

// A realistic Sigma rule must translate to the right severity, MITRE and predicates,
// AND the produced condition must actually match the event it describes (round-trip
// through the native evaluator).
func TestImportSigma_TranslatesAndMatches(t *testing.T) {
	rule := []byte(`
title: Suspicious PowerShell Download Cradle
description: Detects PowerShell download cradles
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    class_name|contains: powershell
    action: exec
  condition: selection
`)
	in, err := ImportSigma(rule)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if in.Name != "Suspicious PowerShell Download Cradle" || in.Severity != "high" {
		t.Fatalf("name/severity wrong: %q / %q", in.Name, in.Severity)
	}
	if len(in.MITRE) != 1 || in.MITRE[0] != "T1059.001" {
		t.Fatalf("mitre wrong: %v", in.MITRE)
	}
	if len(in.Condition.All) != 2 {
		t.Fatalf("expected 2 AND predicates, got %d: %+v", len(in.Condition.All), in.Condition.All)
	}

	// Round-trip: the condition matches a powershell/exec event...
	match := eventstore.NormalizedEvent{ClassName: "Windows PowerShell.exe", Action: "exec"}
	if !in.Condition.Matches(match) {
		t.Fatal("condition should match a powershell exec event")
	}
	// ...and does NOT match an unrelated event.
	noMatch := eventstore.NormalizedEvent{ClassName: "cmd.exe", Action: "exec"}
	if in.Condition.Matches(noMatch) {
		t.Fatal("condition must not match a non-powershell event")
	}
}

// A list value becomes an OR group (Condition.Any); modifiers map correctly.
func TestImportSigma_ListIsOrAndModifiers(t *testing.T) {
	rule := []byte(`
title: Cloud Recon
level: medium
detection:
  selection:
    class_name:
      - Reconnaissance
      - Discovery
    source|startswith: aws
  condition: selection
`)
	in, err := ImportSigma(rule)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(in.Condition.Any) != 2 {
		t.Fatalf("list value should produce a 2-way OR group, got %+v", in.Condition.Any)
	}
	// startswith maps to an anchored regex.
	var sawRegex bool
	for _, p := range in.Condition.All {
		if p.Field == "source" && p.Op == OpRegex && p.Value == "^aws" {
			sawRegex = true
		}
	}
	if !sawRegex {
		t.Fatalf("startswith should map to regex ^aws; All=%+v", in.Condition.All)
	}
	// Matches Discovery from aws-guardduty; not from okta.
	if !in.Condition.Matches(eventstore.NormalizedEvent{ClassName: "Discovery", Source: "aws-guardduty"}) {
		t.Fatal("should match Discovery from an aws source")
	}
	if in.Condition.Matches(eventstore.NormalizedEvent{ClassName: "Discovery", Source: "okta"}) {
		t.Fatal("should not match a non-aws source")
	}
}

// data.<field> mapping: unknown Sigma fields target the normalized payload.
func TestImportSigma_UnknownFieldMapsToData(t *testing.T) {
	rule := []byte(`
title: Cmdline Rule
level: low
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
`)
	in, err := ImportSigma(rule)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if in.Condition.All[0].Field != "data.CommandLine" {
		t.Fatalf("unknown field should map to data.CommandLine, got %q", in.Condition.All[0].Field)
	}
	ev := eventstore.NormalizedEvent{Data: map[string]any{"CommandLine": "invoke-mimikatz -dump"}}
	if !in.Condition.Matches(ev) {
		t.Fatal("should match on data.CommandLine contains mimikatz")
	}
}

// Unsupported constructs must error clearly rather than produce a wrong rule.
func TestImportSigma_UnsupportedErrors(t *testing.T) {
	cases := map[string][]byte{
		"or between selections": []byte("title: t\nlevel: low\ndetection:\n  a: {source: x}\n  b: {source: y}\n  condition: a or b\n"),
		"missing title":         []byte("level: low\ndetection:\n  selection: {source: x}\n  condition: selection\n"),
		"missing condition":     []byte("title: t\nlevel: low\ndetection:\n  selection: {source: x}\n"),
		"invalid yaml":          []byte("title: [unterminated"),
	}
	for name, y := range cases {
		if _, err := ImportSigma(y); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
