// Package entitygraph builds a read-only "blast radius" view for an entity ref
// (host/user/ip): the alerts touching it, the incidents those alerts belong to, the
// correlation clusters on it, and the matched inventory asset (SRS §6.9). It is pure
// composition over existing tenant-scoped stores — it owns no table, so every result
// is confined to the caller's own tenant by the underlying RLS.
package entitygraph

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/correlation"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Graph is the composed view for one entity ref.
type Graph struct {
	Ref          string                    `json:"ref"`
	Asset        *asset.Asset              `json:"asset,omitempty"` // matched inventory asset (nil if unmanaged)
	Alerts       []alert.Alert             `json:"alerts"`
	Incidents    []incident.Incident       `json:"incidents"`
	Correlations []correlation.Correlation `json:"correlations"`
	Summary      Summary                   `json:"summary"`
}

// Summary is the at-a-glance rollup for the entity.
type Summary struct {
	AlertCount       int    `json:"alert_count"`
	IncidentCount    int    `json:"incident_count"`
	OpenIncidents    int    `json:"open_incidents"`
	CorrelationCount int    `json:"correlation_count"`
	MaxSeverity      string `json:"max_severity"`
}

// Narrow read dependencies (satisfied by the respective domain services).
type Alerts interface {
	ListByRef(ctx context.Context, tenantID uuid.UUID, ref string) ([]alert.Alert, error)
}
type Incidents interface {
	GetByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]incident.Incident, error)
}
type Correlations interface {
	ListByEntity(ctx context.Context, tenantID uuid.UUID, entity string) ([]correlation.Correlation, error)
}
type Assets interface {
	FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]asset.Asset, error)
}

var sevRank = map[string]int{"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Service assembles entity graphs.
type Service struct {
	alerts       Alerts
	incidents    Incidents
	correlations Correlations
	assets       Assets
}

// NewService builds the entity-graph service.
func NewService(a Alerts, i Incidents, c Correlations, as Assets) *Service {
	return &Service{alerts: a, incidents: i, correlations: c, assets: as}
}

// Build composes the entity graph for ref in the caller's tenant.
func (s *Service) Build(ctx context.Context, tenantID uuid.UUID, ref string) (*Graph, error) {
	if ref == "" {
		return nil, httpx.ErrBadRequest("ref is required")
	}
	alerts, err := s.alerts.ListByRef(ctx, tenantID, ref)
	if err != nil {
		return nil, httpx.ErrInternal("could not read alerts")
	}
	// The distinct incidents the alerts belong to, fetched in ONE query (no N+1, R2 M-E).
	var ids []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, a := range alerts {
		if a.IncidentID != nil && !seen[*a.IncidentID] {
			seen[*a.IncidentID] = true
			ids = append(ids, *a.IncidentID)
		}
	}
	incidents, err := s.incidents.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, httpx.ErrInternal("could not read incidents")
	}
	openInc := 0
	for i := range incidents {
		if incidents[i].Stage != incident.StageClosed {
			openInc++
		}
	}
	corrs, err := s.correlations.ListByEntity(ctx, tenantID, ref)
	if err != nil {
		return nil, httpx.ErrInternal("could not read correlations")
	}
	var matched *asset.Asset
	if assets, _ := s.assets.FindByRefs(ctx, tenantID, []string{ref}); len(assets) > 0 {
		matched = &assets[0]
	}
	maxSev := ""
	for _, a := range alerts {
		if sevRank[a.Severity] > sevRank[maxSev] {
			maxSev = a.Severity
		}
	}
	return &Graph{
		Ref: ref, Asset: matched, Alerts: alerts, Incidents: incidents, Correlations: corrs,
		Summary: Summary{
			AlertCount: len(alerts), IncidentCount: len(incidents), OpenIncidents: openInc,
			CorrelationCount: len(corrs), MaxSeverity: maxSev,
		},
	}, nil
}
