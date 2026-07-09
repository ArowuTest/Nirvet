package ingestion_test

// §6.5 slice A normalization quality/drift against a migrated Postgres. Gated on NIRVET_TEST_DATABASE_URL.

import (
	"context"
	"os"
	"testing"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func TestNormQuality(t *testing.T) {
	dsn := os.Getenv("NIRVET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set NIRVET_TEST_DATABASE_URL to run normalization quality tests")
	}
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "norm-" + uuid.NewString()})

	nq := ingestion.NewNormQuality(db)
	// A flaky source barely maps (avg 20); a good source maps well (avg 90). Accumulate then flush once.
	for i := 0; i < 3; i++ {
		nq.Record(tn.ID, "flaky", "identity", 0, 20)
	}
	for i := 0; i < 2; i++ {
		nq.Record(tn.ID, "good", "microsoft-defender", 1, 90)
	}
	if err := nq.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	bySource := func() map[string]ingestion.SourceQuality {
		q, err := nq.Quality(ctx, tn.ID)
		if err != nil {
			t.Fatalf("quality: %v", err)
		}
		m := map[string]ingestion.SourceQuality{}
		for _, s := range q {
			m[s.Source] = s
		}
		return m
	}

	q := bySource()
	if f := q["flaky"]; f.Events != 3 || f.AvgConfidence != 20 || !f.Drift {
		t.Fatalf("flaky: expected 3 events avg 20 drift, got %+v", f)
	}
	if g := q["good"]; g.Events != 2 || g.AvgConfidence != 90 || g.Drift || g.Parser != "microsoft-defender" || g.ParserVersion != 1 {
		t.Fatalf("good: expected 2 events avg 90 no-drift parser v1, got %+v", g)
	}

	// Accumulated counts add on re-flush (same day bucket).
	nq.Record(tn.ID, "flaky", "identity", 0, 20)
	if err := nq.Flush(ctx); err != nil {
		t.Fatalf("flush2: %v", err)
	}
	if f := bySource()["flaky"]; f.Events != 4 {
		t.Fatalf("expected accumulated 4 events, got %d", f.Events)
	}

	// Raising the floor above the good source's average now flags it as drift too (config-driven).
	if _, err := nq.SetSettings(ctx, tn.ID, ingestion.NormSettings{MinConfidence: 95, WindowDays: 7}); err != nil {
		t.Fatalf("set settings: %v", err)
	}
	if g := bySource()["good"]; !g.Drift {
		t.Fatalf("good should drift once min_confidence=95, got %+v", g)
	}
	set, err := nq.GetSettings(ctx, tn.ID)
	if err != nil || set.MinConfidence != 95 {
		t.Fatalf("settings round-trip: %+v (err %v)", set, err)
	}

	// Tenant isolation: another tenant sees none of this.
	other, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "norm-other-" + uuid.NewString()})
	if q, _ := nq.Quality(ctx, other.ID); len(q) != 0 {
		t.Fatalf("cross-tenant must see no quality rows, got %d", len(q))
	}
}
