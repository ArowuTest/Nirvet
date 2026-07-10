package fleet

// The scope-resolver is the BOLA boundary of the fleet read. The MA-1 SD-fn only ENFORCES a bound; this
// decides the bound. Whatever Resolve returns is exactly what the operator can see, so it is derived PURELY
// from the authenticated principal (role + server-side bindings) — NEVER from client input — and it fails
// CLOSED (a principal with no fleet/oversight scope → EMPTY set → fleet_alerts()'s zero rows). It never widens.

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
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

// ResolveTargetTenant is the write path's gate (reviewer MA-2/3 #1+#2): it returns the TARGET tenant for a
// fleet write on the given alert, taken FROM THE ALERT ROW (never p.TenantID, never a client id) and only if
// that tenant is inside the caller's principal-resolved fleet scope. Any write handler MUST call this first and
// then act under WithTenant(target). It refuses (ErrForbidden) when the alert is outside the caller's scope —
// including a non-provider's EMPTY scope, so a non-oversight principal has NO cross-tenant write path at all.
func (s *Service) ResolveTargetTenant(ctx context.Context, p auth.Principal, alertID uuid.UUID) (uuid.UUID, error) {
	scope, err := s.resolver.Resolve(ctx, p)
	if err != nil {
		return uuid.Nil, err
	}
	target, err := s.repo.AlertTargetTenant(ctx, alertID, scope)
	if err != nil {
		return uuid.Nil, err
	}
	if target == nil {
		// Out of scope, or the alert does not exist. Deliberately one indistinct refusal — a fleet operator has
		// no need to distinguish "not yours" from "no such alert", and it avoids a cross-tenant existence oracle.
		return uuid.Nil, httpx.ErrForbidden("alert is not within your fleet scope")
	}
	return *target, nil
}
