package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/asset"
	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
)

// Incidents and Alerts are the narrow read dependencies (satisfied by
// incident.Service and alert.Service), keeping evidence decoupled and testable.
type Incidents interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (*incident.Incident, error)
	Timeline(ctx context.Context, tenantID, id uuid.UUID) ([]incident.TimelineEntry, error)
}

// Alerts resolves the alerts promoted into an incident.
type Alerts interface {
	ListByIncident(ctx context.Context, tenantID, incidentID uuid.UUID) ([]alert.Alert, error)
}

// Assets resolves inventory assets by their canonical refs (affected-asset context).
type Assets interface {
	FindByRefs(ctx context.Context, tenantID uuid.UUID, refs []string) ([]asset.Asset, error)
}

// Service assembles evidence packs read-only from the case, alert, event, asset and
// audit stores. Every read is tenant-scoped, so a pack can only ever contain the
// caller's own tenant data.
type Service struct {
	incidents Incidents
	alerts    Alerts
	events    eventstore.EventStore
	assets    Assets
	db        *database.DB
}

// NewService builds the evidence service.
func NewService(incidents Incidents, alerts Alerts, events eventstore.EventStore, assets Assets, db *database.DB) *Service {
	return &Service{incidents: incidents, alerts: alerts, events: events, assets: assets, db: db}
}

// Build assembles the evidence pack for an incident in the caller's tenant, stamped
// at `now`. Events are the distinct events referenced by the incident's alerts; the
// audit trail is every log row whose action/target carries the incident id.
func (s *Service) Build(ctx context.Context, p auth.Principal, incidentID uuid.UUID, now time.Time) (*Pack, error) {
	inc, err := s.incidents.Get(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, httpx.ErrNotFound("incident not found")
	}
	timeline, err := s.incidents.Timeline(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, httpx.ErrInternal("could not read timeline")
	}
	alerts, err := s.alerts.ListByIncident(ctx, p.TenantID, incidentID)
	if err != nil {
		return nil, httpx.ErrInternal("could not read alerts")
	}
	// The underlying events are the distinct event ids the incident's alerts reference.
	var ids []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, a := range alerts {
		if a.EventID != nil && !seen[*a.EventID] {
			seen[*a.EventID] = true
			ids = append(ids, *a.EventID)
		}
	}
	events, err := s.events.GetByIDs(ctx, p.TenantID, ids)
	if err != nil {
		return nil, httpx.ErrInternal("could not read events")
	}
	// Affected assets (§6.15): the distinct actor/target refs the alerts touch,
	// resolved against the tenant's inventory.
	var refs []string
	seenRef := map[string]bool{}
	for _, a := range alerts {
		for _, ref := range []string{a.TargetRef, a.ActorRef} {
			if ref != "" && !seenRef[ref] {
				seenRef[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	assets, err := s.assets.FindByRefs(ctx, p.TenantID, refs)
	if err != nil {
		return nil, httpx.ErrInternal("could not read assets")
	}
	auditRows, err := audit.FindByActionContains(ctx, s.db, p.TenantID, incidentID.String(), 500)
	if err != nil {
		return nil, httpx.ErrInternal("could not read audit trail")
	}
	pack := &Pack{
		SchemaVersion: PackSchemaVersion,
		GeneratedAt:   now,
		GeneratedBy:   p.Email,
		TenantID:      p.TenantID,
		Incident:      inc,
		Timeline:      timeline,
		Alerts:        alerts,
		Events:        events,
		Assets:        assets,
		Audit:         auditRows,
	}
	pack.Manifest = buildManifest(pack)
	return pack, nil
}

// checksum returns the hex SHA-256 of the canonical JSON of v.
func checksum(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// buildManifest computes per-section checksums, counts, and an overall pack checksum
// over the (stably-ordered) section checksums.
func buildManifest(p *Pack) Manifest {
	sc := map[string]string{
		"incident": checksum(p.Incident),
		"timeline": checksum(p.Timeline),
		"alerts":   checksum(p.Alerts),
		"events":   checksum(p.Events),
		"assets":   checksum(p.Assets),
		"audit":    checksum(p.Audit),
	}
	counts := map[string]int{
		"timeline": len(p.Timeline),
		"alerts":   len(p.Alerts),
		"events":   len(p.Events),
		"assets":   len(p.Assets),
		"audit":    len(p.Audit),
	}
	keys := make([]string, 0, len(sc))
	for k := range sc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	concat := ""
	for _, k := range keys {
		concat += k + ":" + sc[k] + ";"
	}
	h := sha256.Sum256([]byte(concat))
	return Manifest{
		Algorithm:       "sha256",
		SectionChecksum: sc,
		Counts:          counts,
		PackChecksum:    hex.EncodeToString(h[:]),
	}
}
