package investigation

// §6.9 #124 I-4/I-5 — the structured timeline (integration, over real events under RLS) and the data-gap panel
// composition (unit, with fakes: the underlying readers are each tenant-scoped and tested in their own packages).

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/connector"
	"github.com/ArowuTest/nirvet/internal/detection"
	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// I-4: the forensic timeline returns an entity's events in ascending chronological order and records the read-audit.
func TestTimeline_ChronologicalAndAudit(t *testing.T) {
	db := invDB(t)
	tid := invTenant(t, db)
	now := time.Now()
	seedEvent(t, db, tid, now.Add(-2*time.Hour), "high", "host:WEB-1", "s") // older
	seedEvent(t, db, tid, now.Add(-1*time.Hour), "low", "host:WEB-1", "s")  // newer

	tl, err := NewService(NewRepository(db)).GetTimeline(context.Background(), analystOf(tid), "host:WEB-1", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(tl.Entries) != 2 {
		t.Fatalf("expected 2 timeline entries for the entity, got %d", len(tl.Entries))
	}
	if !tl.Entries[0].EventTime.Before(tl.Entries[1].EventTime) {
		t.Fatal("timeline entries must be in ascending chronological order")
	}
	if tl.Entries[0].Entity != "host:WEB-1" || tl.Entries[0].Lane != "event" || tl.Entries[0].Source == "" {
		t.Fatalf("timeline entry must carry the forensic fields: %+v", tl.Entries[0])
	}
	var n int
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM investigation_query_audit WHERE tenant_id=$1 AND kind='entity_read'`, tid).Scan(&n)
	}); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if n < 1 {
		t.Fatal("a timeline read must be recorded in the read-path audit (INV-007)")
	}
}

// I-5: fakes for the three tenant-scoped readers, so the test isolates the panel COMPOSITION (drift is filtered to
// Drift==true; coverage + silence pass through).
type fakeCov struct{ gaps []detection.CoverageGap }

func (f fakeCov) CoverageGaps(context.Context, uuid.UUID) ([]detection.CoverageGap, error) { return f.gaps, nil }

type fakeDrift struct{ q []ingestion.SourceQuality }

func (f fakeDrift) Quality(context.Context, uuid.UUID) ([]ingestion.SourceQuality, error) { return f.q, nil }

type fakeSilence struct{ s []connector.SilentSource }

func (f fakeSilence) TenantSilentHostSources(context.Context, uuid.UUID, time.Duration) ([]connector.SilentSource, error) {
	return f.s, nil
}

func TestDataGaps_UnifiesAndFiltersDrift(t *testing.T) {
	svc := NewDataGapService(
		fakeCov{gaps: []detection.CoverageGap{{Name: "rule-1"}}},
		fakeDrift{q: []ingestion.SourceQuality{{Source: "a", Drift: true}, {Source: "b", Drift: false}}},
		fakeSilence{s: []connector.SilentSource{{Name: "osquery-1"}}},
	)
	res := svc.Get(context.Background(), analyst())
	if len(res.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps must pass through, got %d", len(res.CoverageGaps))
	}
	if len(res.SilentSources) != 1 {
		t.Fatalf("silent sources must pass through, got %d", len(res.SilentSources))
	}
	if len(res.DriftingSources) != 1 || res.DriftingSources[0].Source != "a" {
		t.Fatalf("only drifting sources (Drift==true) must be surfaced, got %+v", res.DriftingSources)
	}
}
