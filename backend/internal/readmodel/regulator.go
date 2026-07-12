package readmodel

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ScopeResolver yields the tenant set a regulator/oversight principal may see, derived PURELY from the principal
// (never client input) and fail-closed to an empty set when no grant applies. posture.Service satisfies it.
type ScopeResolver interface {
	TenantScope(ctx context.Context, p auth.Principal) ([]uuid.UUID, error)
}

// RegulatorRepo reads the metadata-only, bound-array SECURITY DEFINER functions (migration 0102) under
// WithSystem — the ONLY cross-tenant read path for the regulator audience. It returns metadata rows
// (IncidentMeta/AlertMeta); incident/alert CONTENT is never selected, so it never reaches the app.
type RegulatorRepo struct{ db *database.DB }

// NewRegulatorRepo builds the repo.
func NewRegulatorRepo(db *database.DB) *RegulatorRepo { return &RegulatorRepo{db: db} }

// IncidentMetaForTenants returns per-incident metadata across the scoped tenants. An empty scope yields no rows
// (the SD function is fail-closed on an empty/NULL array), so a regulator with no grant sees nothing.
func (r *RegulatorRepo) IncidentMetaForTenants(ctx context.Context, tenantIDs []uuid.UUID) ([]IncidentMeta, error) {
	var out []IncidentMeta
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT category, severity, stage, ack_breached, resolve_breached FROM incident_meta_for_tenants($1)`,
			tenantIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m IncidentMeta
			if err := rows.Scan(&m.Category, &m.Severity, &m.Stage, &m.AckBreached, &m.ResolveBreached); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// AlertMetaForTenants returns per-alert metadata across the scoped tenants (fail-closed on empty scope).
func (r *RegulatorRepo) AlertMetaForTenants(ctx context.Context, tenantIDs []uuid.UUID) ([]AlertMeta, error) {
	var out []AlertMeta
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT severity, status FROM alert_meta_for_tenants($1)`, tenantIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m AlertMeta
			if err := rows.Scan(&m.Severity, &m.Status); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}
