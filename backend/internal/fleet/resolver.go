package fleet

// The scope-resolver is the BOLA boundary of the fleet read. The MA-1 SD-fn only ENFORCES a bound; this
// decides the bound. Whatever Resolve returns is exactly what the operator can see, so it is derived PURELY
// from the authenticated principal (role + server-side bindings) — NEVER from client input — and it fails
// CLOSED (a principal with no fleet/oversight scope → EMPTY set → fleet_alerts()'s zero rows). It never widens.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ScopeResolver maps an authenticated principal to the tenant-set it may read across the fleet.
type ScopeResolver struct{ db *database.DB }

// Resolve returns the tenant-set the principal may read, derived purely from the principal. On this dedicated
// single-operator instance, provider/SOC staff see the whole fleet (every tenant; `operator_id` filtering is
// the V2 seam). Everyone else — customer users, and any unknown/garbage role — resolves to an EMPTY set.
//
// Org-sub-admin (own-org) and payer/anchor (own-account) resolvers are FOLLOW-ON: they need net-new
// principal→org / principal→account bindings (and org-sub-admin a net-new role). Until those land, such a
// principal is non-provider → EMPTY (fail-closed, never widened) — safe by default, not silently broad.
func (r *ScopeResolver) Resolve(ctx context.Context, p auth.Principal) ([]uuid.UUID, error) {
	if auth.IsProviderRole(p.Role) {
		return r.allInstanceTenants(ctx)
	}
	return nil, nil // fail-closed: no fleet scope for a non-provider principal
}

// allInstanceTenants lists every tenant in the instance — the fleet on a dedicated single-operator instance.
// `tenants` is the global registry (no RLS), read under WithSystem. (Keyset pagination for a very large fleet
// is a documented console/soak carry-forward, not a correctness concern here.)
func (r *ScopeResolver) allInstanceTenants(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if e := rows.Scan(&id); e != nil {
				return e
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// Service is the fleet console read service: resolve the principal's scope, then read within it.
type Service struct {
	resolver *ScopeResolver
	repo     *Repository
}

// NewService wires the fleet read service.
func NewService(db *database.DB) *Service {
	return &Service{resolver: &ScopeResolver{db: db}, repo: NewRepository(db)}
}

// Alerts returns the fleet alert queue the principal may see. Scope is principal-derived; a non-oversight
// principal gets an empty scope → zero alerts (defense-in-depth; the route is ALSO role-gated to providers).
func (s *Service) Alerts(ctx context.Context, p auth.Principal, status string, limit int) ([]FleetAlert, error) {
	tenantIDs, err := s.resolver.Resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	return s.repo.FleetAlerts(ctx, tenantIDs, status, limit)
}
