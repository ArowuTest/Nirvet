package threatintel

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// primeCache seeds the enricher's per-tenant cache directly so matching logic can
// be tested without a database (the cache is normally filled from the repo).
func primeCache(e *Enricher, tenantID uuid.UUID, inds []Indicator) {
	e.mu.Lock()
	e.cache[tenantID] = entry{inds: inds, expires: time.Now().Add(time.Hour)}
	e.mu.Unlock()
}

func TestEnrich_MatchesCaseInsensitiveAndDedupes(t *testing.T) {
	e := NewEnricher(nil) // repo unused: cache is primed
	tid := uuid.New()
	primeCache(e, tid, []Indicator{
		{Value: "evil.com", Type: "domain", Score: 90, TLP: "red", Tags: []string{"c2"}},
		{Value: "10.0.0.5", Type: "ip", Score: 70, TLP: "amber"},
		{Value: "unused.example", Type: "domain", Score: 10},
	})

	matches, err := e.Enrich(context.Background(), tid, []string{
		"connection to EVIL.COM/login", // case-insensitive hit on evil.com
		"src=10.0.0.5",                 // hit on the IP
		"http://evil.com/x",            // same indicator again -> must dedupe
		"",                             // empty candidate ignored
	})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 unique matches (evil.com, 10.0.0.5), got %d: %+v", len(matches), matches)
	}
	byVal := map[string]Match{}
	for _, m := range matches {
		byVal[m.Value] = m
	}
	if m, ok := byVal["evil.com"]; !ok || m.Score != 90 || m.TLP != "red" {
		t.Fatalf("evil.com match wrong: %+v", m)
	}
	if _, ok := byVal["unused.example"]; ok {
		t.Fatal("indicator with no candidate hit must not match")
	}
}

func TestEnrich_NoIndicatorsNoMatches(t *testing.T) {
	e := NewEnricher(nil)
	tid := uuid.New()
	primeCache(e, tid, nil)
	matches, err := e.Enrich(context.Background(), tid, []string{"anything"})
	if err != nil || len(matches) != 0 {
		t.Fatalf("expected no matches with empty watchlist: n=%d err=%v", len(matches), err)
	}
}

// invalidate must drop the cached entry so the next Enrich reloads from the repo.
func TestEnricher_InvalidateDropsCache(t *testing.T) {
	e := NewEnricher(nil)
	tid := uuid.New()
	primeCache(e, tid, []Indicator{{Value: "x", Type: "host"}})
	e.invalidate(tid)
	e.mu.Lock()
	_, ok := e.cache[tid]
	e.mu.Unlock()
	if ok {
		t.Fatal("invalidate should have removed the tenant cache entry")
	}
}
