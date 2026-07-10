package investigation

// §6.9 #124 I-3 — typed entity profile + pivot (INV-003/004). This is pure composition over the existing
// entitygraph.Service (which itself is tenant-scoped composition under RLS), so a profile/pivot can only ever see the
// caller's own tenant — a neighbor is derived from the tenant's OWN alerts, never from a client-supplied cross-tenant
// ref. Every read is recorded in the read-path audit (INV-007), same as a hunt query.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/entitygraph"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// EntityGrapher is the narrow read dependency (satisfied by *entitygraph.Service). Keeping it an interface keeps
// investigation decoupled and the pivot logic unit-testable with a fake.
type EntityGrapher interface {
	Build(ctx context.Context, tenantID uuid.UUID, ref string) (*entitygraph.Graph, error)
}

// EntityService serves the typed entity profile + pivot.
type EntityService struct {
	grapher EntityGrapher
	repo    *Repository
}

// NewEntityService builds the service.
func NewEntityService(grapher EntityGrapher, repo *Repository) *EntityService {
	return &EntityService{grapher: grapher, repo: repo}
}

// EntityProfile is the typed entity plus its blast-radius graph (related alerts/incidents/correlations/asset) — the
// INV-001 unified view's data, and the INV-004 pivot to related records.
type EntityProfile struct {
	Entity Entity             `json:"entity"`
	Graph  *entitygraph.Graph `json:"graph"`
}

// GetProfile resolves a typed entity and composes its blast-radius graph.
func (s *EntityService) GetProfile(ctx context.Context, p auth.Principal, ref string) (EntityProfile, error) {
	e, err := ParseEntity(ref)
	if err != nil {
		return EntityProfile{}, err
	}
	g, err := s.grapher.Build(ctx, p.TenantID, e.Ref())
	if err != nil {
		return EntityProfile{}, err
	}
	if err := s.repo.WriteQueryAudit(ctx, p.TenantID, p.UserID, "entity_read",
		map[string]string{"ref": e.Ref(), "op": "profile"}, len(g.Alerts)); err != nil {
		return EntityProfile{}, err
	}
	return EntityProfile{Entity: e, Graph: g}, nil
}

// Neighbor is a related entity discovered by pivoting: it co-occurred with the center on a shared alert.
type Neighbor struct {
	Entity   Entity    `json:"entity"`
	Via      string    `json:"via"` // "alert"
	AlertID  uuid.UUID `json:"alert_id"`
	Severity string    `json:"severity"`
}

// EntityGraphView is the typed node-edge pivot (INV-004): the center entity + its neighbor entities.
type EntityGraphView struct {
	Center    Entity     `json:"center"`
	Neighbors []Neighbor `json:"neighbors"`
}

// Pivot traverses from an entity to its neighbor entities — the OTHER actor/target ref on each alert touching the
// center. Neighbors are bounded by the configured MaxLimit (reusing the cost-ceiling seam) so the fan-out is capped.
func (s *EntityService) Pivot(ctx context.Context, p auth.Principal, ref string) (EntityGraphView, error) {
	e, err := ParseEntity(ref)
	if err != nil {
		return EntityGraphView{}, err
	}
	g, err := s.grapher.Build(ctx, p.TenantID, e.Ref())
	if err != nil {
		return EntityGraphView{}, err
	}
	limit := s.repo.LoadLimits(ctx).MaxLimit
	view := EntityGraphView{Center: e}
	seen := map[string]bool{e.Ref(): true}
	for _, a := range g.Alerts {
		for _, other := range []string{a.ActorRef, a.TargetRef} {
			if other == "" || seen[other] {
				continue
			}
			ne, perr := ParseEntity(other)
			if perr != nil {
				continue // a ref that is not a typed entity is skipped, not surfaced
			}
			seen[other] = true
			view.Neighbors = append(view.Neighbors, Neighbor{Entity: ne, Via: "alert", AlertID: a.ID, Severity: a.Severity})
			if len(view.Neighbors) >= limit {
				break
			}
		}
		if len(view.Neighbors) >= limit {
			break
		}
	}
	if err := s.repo.WriteQueryAudit(ctx, p.TenantID, p.UserID, "entity_read",
		map[string]string{"ref": e.Ref(), "op": "pivot"}, len(view.Neighbors)); err != nil {
		return EntityGraphView{}, err
	}
	return view, nil
}
