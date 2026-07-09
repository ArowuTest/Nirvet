package threatintel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestExtractObservable(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		pattern string
		raw     string
		want    string
	}{
		{"ipv4 indicator", "indicator", "[ipv4-addr:value = '1.2.3.4']", "", "1.2.3.4"},
		{"domain indicator", "indicator", "[domain-name:value = 'evil.example']", "", "evil.example"},
		{"hash value after property key", "indicator", "[file:hashes.'SHA-256' = 'deadbeef']", "", "deadbeef"},
		{"sco value from raw", "domain-name", "", `{"type":"domain-name","value":"bad.example"}`, "bad.example"},
		{"sdo has no observable", "malware", "", `{"type":"malware","name":"x"}`, ""},
		{"indicator without literal", "indicator", "[ipv4-addr:value MATCHES foo]", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractObservable(c.typ, c.pattern, json.RawMessage(c.raw))
			if got != c.want {
				t.Fatalf("extractObservable(%q,%q,%q) = %q, want %q", c.typ, c.pattern, c.raw, got, c.want)
			}
		})
	}
}

func TestTokenContains(t *testing.T) {
	// True positives: delimited occurrence.
	if !tokenContains("src=8.8.8.8;dst", "8.8.8.8") {
		t.Fatal("delimited IP should match")
	}
	if !tokenContains("connect to evil.com/login", "evil.com") {
		t.Fatal("delimited domain should match")
	}
	// False positives that plain Contains would wrongly flag:
	if tokenContains("18.8.8.80", "8.8.8.8") {
		t.Fatal("8.8.8.8 must NOT match inside 18.8.8.80")
	}
	if tokenContains("evil.com", ".com") {
		t.Fatal(".com must not token-match evil.com (leading boundary is alphanumeric)")
	}
	if tokenContains("prefix", "pre") {
		t.Fatal("substring without trailing boundary must not match")
	}
}

func TestValidStixType(t *testing.T) {
	if !validStixType("indicator") || !validStixType("attack-pattern") || !validStixType("ipv4-addr") {
		t.Fatal("known STIX types must validate")
	}
	if validStixType("not-a-stix-type") || validStixType("") {
		t.Fatal("unknown types must be rejected")
	}
}

func TestTLPFromMarkings(t *testing.T) {
	if got := tlpFromMarkings([]string{"marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}); got != "red" {
		t.Fatalf("TLP:RED marking should map to red, got %q", got)
	}
	if got := tlpFromMarkings([]string{"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"}); got != "clear" {
		t.Fatalf("TLP:WHITE marking should normalise to clear, got %q", got)
	}
	if got := tlpFromMarkings(nil); got != "amber" {
		t.Fatalf("unmarked object should default to amber, got %q", got)
	}
}

func TestValidTLPAndClamp(t *testing.T) {
	if validTLP("amber+strict") != "amber+strict" {
		t.Fatal("amber+strict is a valid TLP 2.0 marking")
	}
	if validTLP("purple") != "amber" {
		t.Fatal("unknown TLP must fall back to amber")
	}
	if clampConfidence(-5) != 0 || clampConfidence(250) != 100 || clampConfidence(60) != 60 {
		t.Fatal("confidence must clamp to 0-100")
	}
}

func TestParseBundleObject(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"indicator",
		"id":"indicator--11111111-1111-1111-1111-111111111111",
		"spec_version":"2.1",
		"pattern":"[ipv4-addr:value = '9.9.9.9']",
		"pattern_type":"stix",
		"confidence":90,
		"labels":["malicious-activity"],
		"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"command-and-control"}],
		"object_marking_refs":["marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]
	}`)
	o, ok := parseBundleObject(raw)
	if !ok {
		t.Fatal("valid indicator must parse")
	}
	if o.Value != "9.9.9.9" {
		t.Fatalf("observable not extracted: %q", o.Value)
	}
	if o.TLP != "red" {
		t.Fatalf("TLP not derived from markings: %q", o.TLP)
	}
	if o.Confidence != 90 || len(o.Labels) != 1 || len(o.KillChainPhases) != 1 || o.KillChainPhases[0] != "command-and-control" {
		t.Fatalf("fields mismapped: %+v", o)
	}

	// Unknown type / missing id -> ignored.
	if _, ok := parseBundleObject(json.RawMessage(`{"type":"nope","id":"x--1"}`)); ok {
		t.Fatal("unknown type must be rejected")
	}
	if _, ok := parseBundleObject(json.RawMessage(`{"type":"indicator"}`)); ok {
		t.Fatal("object without id must be rejected")
	}
}

// TestEnrich_StixObservableMatches primes the enricher cache with a STIX observable and asserts a hit
// carries STIX provenance (object id, confidence, labels, kill-chain) — distinct from a watchlist hit.
func TestEnrich_StixObservableMatches(t *testing.T) {
	e := NewEnricher(nil)
	tid := uuid.New()
	obs := []stixObservable{{
		ID: "indicator--abc", Type: "ipv4-addr", Value: "9.9.9.9", Confidence: 90, TLP: "red",
		Labels: []string{"c2"}, KillChain: []string{"command-and-control"}, Created: time.Now(),
	}}
	e.mu.Lock()
	e.cache[tid] = entry{
		inds: []Indicator{{Value: "manual.example", Type: "domain", Score: 40, TLP: "green", Tags: []string{"watch"}}},
		obs:  obs,
		// slice B: the enricher matches the expanded per-literal entries; settings default (no decay floor).
		stix:      []stixMatchEntry{{value: "9.9.9.9", obs: &obs[0]}},
		sightings: map[string]int{},
		settings:  DefaultTISettings(),
		expires:   time.Now().Add(time.Hour),
	}
	e.mu.Unlock()

	matches, err := e.Enrich(context.Background(), tid, []string{"outbound to 9.9.9.9:443", "visit manual.example"})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected watchlist + stix match, got %d: %+v", len(matches), matches)
	}
	byID := map[string]Match{}
	for _, m := range matches {
		byID[m.Source] = m
	}
	stix := byID["stix"]
	if stix.ObjectID != "indicator--abc" || stix.Confidence != 90 || stix.TLP != "red" ||
		len(stix.KillChain) != 1 || len(stix.Labels) != 1 {
		t.Fatalf("stix match lost provenance: %+v", stix)
	}
	if byID["watchlist"].Value != "manual.example" || byID["watchlist"].Score != 40 {
		t.Fatalf("watchlist match wrong: %+v", byID["watchlist"])
	}
}
