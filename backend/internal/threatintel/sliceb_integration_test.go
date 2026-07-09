package threatintel_test

// §6.10 slice B (multi-value patterns, decay, sightings) against a migrated Postgres. Gated on
// NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/ArowuTest/nirvet/internal/threatintel"
	"github.com/google/uuid"
)

func TestThreatIntelSliceB(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "ti-" + uuid.NewString()})

	repo := threatintel.NewRepository(db)
	enr := threatintel.NewEnricher(repo)
	svc := threatintel.NewService(repo, enr)
	now := time.Now()

	stixHits := func(ip string) []threatintel.Match {
		ms, e := enr.Enrich(ctx, tn.ID, []string{"conn to " + ip + ":443 seen"})
		if e != nil {
			t.Fatalf("enrich %s: %v", ip, e)
		}
		var out []threatintel.Match
		for _, m := range ms {
			if m.Source == "stix" {
				out = append(out, m)
			}
		}
		return out
	}

	// 1. Compound multi-value indicator (fresh) must match EITHER branch (slice A kept only the first).
	comp, err := svc.AddStix(ctx, tn.ID, threatintel.StixInput{
		Type: "indicator", Confidence: 60, ValidFrom: &now,
		Pattern: `[ipv4-addr:value = '1.1.1.1' OR ipv4-addr:value = '2.2.2.2']`,
	})
	if err != nil {
		t.Fatalf("add compound: %v", err)
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		if h := stixHits(ip); len(h) != 1 {
			t.Fatalf("compound indicator must match branch %s, got %d hits", ip, len(h))
		}
	}

	// 2. Decay: a 90-day-old (3 half-lives) confidence-80 IOC decays to ~10.
	old := now.Add(-90 * 24 * time.Hour)
	if _, err := svc.AddStix(ctx, tn.ID, threatintel.StixInput{
		Type: "indicator", Confidence: 80, ValidFrom: &old,
		Pattern: `[ipv4-addr:value = '3.3.3.3']`,
	}); err != nil {
		t.Fatalf("add decayed: %v", err)
	}
	// Under the default floor (0) it still matches (decayed, not expired).
	if h := stixHits("3.3.3.3"); len(h) != 1 || h[0].Confidence > 20 {
		t.Fatalf("decayed IOC should match with a low effective confidence, got %+v", h)
	}
	// Raise the freshness floor to 50 → the ~10 IOC drops out; the fresh compound (60) stays.
	if _, err := svc.SetSettings(ctx, tn.ID, threatintel.TISettings{DecayHalfLifeDays: 30, MinEffectiveConfidence: 50, SightingBoostCap: 20}); err != nil {
		t.Fatalf("set settings: %v", err)
	}
	if h := stixHits("3.3.3.3"); len(h) != 0 {
		t.Fatalf("decayed IOC below floor must stop matching, got %d", len(h))
	}
	fresh := stixHits("1.1.1.1")
	if len(fresh) != 1 || fresh[0].Confidence != 60 {
		t.Fatalf("fresh IOC above floor should match at confidence 60, got %+v", fresh)
	}

	// 3. Sightings corroboration boosts effective confidence (60 + min(30, cap 20) = 80).
	bundle := fmt.Sprintf(`{"type":"bundle","id":"bundle--%s","objects":[`+
		`{"type":"sighting","id":"sighting--%s","spec_version":"2.1","sighting_of_ref":%q,"count":30}]}`,
		uuid.NewString(), uuid.NewString(), comp.ID)
	if _, err := svc.ImportBundle(ctx, tn.ID, json.RawMessage(bundle)); err != nil {
		t.Fatalf("import sighting bundle: %v", err)
	}
	boosted := stixHits("1.1.1.1")
	if len(boosted) != 1 || boosted[0].Confidence != 80 {
		t.Fatalf("sighting boost want confidence 80, got %+v", boosted)
	}

	// 4. Settings round-trip.
	got, err := svc.Settings(ctx, tn.ID)
	if err != nil || got.MinEffectiveConfidence != 50 || got.SightingBoostCap != 20 || got.DecayHalfLifeDays != 30 {
		t.Fatalf("settings round-trip: %+v (err %v)", got, err)
	}

	// 5. Tenant isolation: another tenant sees none of these IOCs.
	other, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "ti-other-" + uuid.NewString()})
	if ms, _ := enr.Enrich(ctx, other.ID, []string{"conn to 1.1.1.1:443"}); len(ms) != 0 {
		t.Fatalf("cross-tenant must not see IOCs, got %d", len(ms))
	}
}
