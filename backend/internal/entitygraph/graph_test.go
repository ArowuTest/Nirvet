package entitygraph

// Pure unit tests (no DB) for entity-graph composition (GC-3). The four read dependencies are interfaces, so
// fakes drive the full Build path: incident-id de-duplication (no N+1), open-incident counting, max-severity
// rollup, asset matching, and the ref-required guard.

import (
	"context"
	"errors"
	"testing"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

type fakeAlerts struct{ out []alert.Alert }

func (f fakeAlerts) ListByRef(context.Context, uuid.UUID, string) ([]alert.Alert, error) {
	return f.out, nil
}

type fakeIncidents struct {
	out      []incident.Incident
	gotIDs   []uuid.UUID
	captured bool
}

func (f *fakeIncidents) GetByIDs(_ context.Context, _ uuid.UUID, ids []uuid.UUID) ([]incident.Incident, error) {
	f.gotIDs = ids
	f.captured = true
	return f.out, nil
}

type fakeCorrelations struct{ out []correlation.Correlation }

func (f fakeCorrelations) ListByEntity(context.Context, uuid.UUID, string) ([]correlation.Correlation, error) {
	return f.out, nil
}

type fakeAssets struct{ out []asset.Asset }

func (f fakeAssets) FindByRefs(context.Context, uuid.UUID, []string) ([]asset.Asset, error) {
	return f.out, nil
}

func TestBuild_RefRequired(t *testing.T) {
	svc := NewService(fakeAlerts{}, &fakeIncidents{}, fakeCorrelations{}, fakeAssets{})
	_, err := svc.Build(context.Background(), uuid.New(), "")
	var api *httpx.APIError
	if !errors.As(err, &api) || api.Code != "bad_request" {
		t.Fatalf("expected bad_request for empty ref, got %v", err)
	}
}

func TestBuild_ComposesAndDedupes(t *testing.T) {
	incA, incB := uuid.New(), uuid.New()
	alerts := []alert.Alert{
		{Severity: "low", IncidentID: &incA},
		{Severity: "high", IncidentID: &incA}, // same incident → must dedupe
		{Severity: "medium", IncidentID: &incB},
		{Severity: "informational"}, // no incident → contributes no id
	}
	inc := &fakeIncidents{out: []incident.Incident{
		{ID: incA, Stage: incident.StageTriage},
		{ID: incB, Stage: incident.StageClosed},
	}}
	assets := fakeAssets{out: []asset.Asset{{Ref: "host:FIN-01"}}}
	svc := NewService(fakeAlerts{out: alerts}, inc, fakeCorrelations{out: []correlation.Correlation{{}}}, assets)

	g, err := svc.Build(context.Background(), uuid.New(), "host:FIN-01")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// De-dup: two distinct incident ids fetched in ONE call (no N+1).
	if !inc.captured || len(inc.gotIDs) != 2 {
		t.Fatalf("expected 2 distinct incident ids in one GetByIDs call, got %v", inc.gotIDs)
	}
	if g.Summary.AlertCount != 4 {
		t.Fatalf("alert count = %d, want 4", g.Summary.AlertCount)
	}
	if g.Summary.IncidentCount != 2 {
		t.Fatalf("incident count = %d, want 2", g.Summary.IncidentCount)
	}
	if g.Summary.OpenIncidents != 1 { // A open (triage), B closed
		t.Fatalf("open incidents = %d, want 1", g.Summary.OpenIncidents)
	}
	if g.Summary.CorrelationCount != 1 {
		t.Fatalf("correlation count = %d, want 1", g.Summary.CorrelationCount)
	}
	if g.Summary.MaxSeverity != "high" {
		t.Fatalf("max severity = %q, want high", g.Summary.MaxSeverity)
	}
	if g.Asset == nil || g.Asset.Ref != "host:FIN-01" {
		t.Fatalf("expected matched asset, got %+v", g.Asset)
	}
}
