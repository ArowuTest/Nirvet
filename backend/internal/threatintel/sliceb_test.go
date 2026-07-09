package threatintel

import (
	"reflect"
	"testing"
	"time"
)

func TestExtractPatternValues(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
	}{
		{`[ipv4-addr:value = '1.2.3.4']`, []string{"1.2.3.4"}},
		{`[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']`, []string{"1.2.3.4", "5.6.7.8"}},
		{`[file:hashes.'SHA-256' = 'abc' AND file:name = 'evil.exe']`, []string{"abc", "evil.exe"}},
		{`[ipv4-addr:value = '9.9.9.9' OR ipv4-addr:value = '9.9.9.9']`, []string{"9.9.9.9"}}, // dedup
		{`[domain-name:value = '']`, nil}, // empty literal dropped
		{`no brackets no quotes`, nil},
	}
	for _, c := range cases {
		got := extractPatternValues(c.pattern)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("extractPatternValues(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestObservableValues(t *testing.T) {
	// Indicator → all pattern literals; SCO → the single extracted value.
	if got := observableValues("indicator", `[url:value = 'http://a' OR url:value = 'http://b']`, "http://a"); !reflect.DeepEqual(got, []string{"http://a", "http://b"}) {
		t.Fatalf("indicator multi-value: got %v", got)
	}
	if got := observableValues("ipv4-addr", "", "8.8.8.8"); !reflect.DeepEqual(got, []string{"8.8.8.8"}) {
		t.Fatalf("sco value: got %v", got)
	}
}

func TestEffectiveConfidence_Decay(t *testing.T) {
	set := TISettings{DecayHalfLifeDays: 30, MinEffectiveConfidence: 0, SightingBoostCap: 20}
	// Age 0 → full; 1 half-life → half; 2 → quarter (rounded).
	if v := effectiveConfidence(80, 0, 0, set); v != 80 {
		t.Fatalf("age 0 want 80, got %d", v)
	}
	if v := effectiveConfidence(80, 30, 0, set); v != 40 {
		t.Fatalf("1 half-life want 40, got %d", v)
	}
	if v := effectiveConfidence(80, 60, 0, set); v != 20 {
		t.Fatalf("2 half-lives want 20, got %d", v)
	}
}

func TestEffectiveConfidence_SightingBoostAndClamp(t *testing.T) {
	set := TISettings{DecayHalfLifeDays: 30, MinEffectiveConfidence: 0, SightingBoostCap: 20}
	// Boost applied AFTER decay: 40 (decayed) + min(50,20 cap) = 60.
	if v := effectiveConfidence(80, 30, 50, set); v != 60 {
		t.Fatalf("decay+boost want 60, got %d", v)
	}
	// Clamp to 100: base 100, no decay, big boost.
	noDecay := TISettings{DecayHalfLifeDays: 3650, SightingBoostCap: 100}
	if v := effectiveConfidence(100, 0, 100, noDecay); v != 100 {
		t.Fatalf("clamp want 100, got %d", v)
	}
}

func TestAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)
	created := now.Add(-10 * 24 * time.Hour)
	vf := now.Add(-4 * 24 * time.Hour)
	// valid_from preferred over created.
	if d := ageDays(&vf, created, now); d < 3.9 || d > 4.1 {
		t.Fatalf("valid_from age want ~4, got %v", d)
	}
	// no valid_from → created.
	if d := ageDays(nil, created, now); d < 9.9 || d > 10.1 {
		t.Fatalf("created age want ~10, got %v", d)
	}
	// future valid_from → 0, never negative.
	future := now.Add(48 * time.Hour)
	if d := ageDays(&future, created, now); d != 0 {
		t.Fatalf("future want 0, got %v", d)
	}
}

func TestDefaultTISettings(t *testing.T) {
	d := DefaultTISettings()
	if d.DecayHalfLifeDays != 30 || d.MinEffectiveConfidence != 0 || d.SightingBoostCap != 20 {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}
