// Package fleet is the operator fleet console's bounded cross-tenant READ primitive (Ghana operator seam #1).
//
// The cross-tenant read runs through the fleet_alerts() SECURITY DEFINER function (mig 0083). Inside that
// function RLS is inert (it executes as the superuser definer), so the tenant-set passed here is the ONLY
// guard (MA-1). The tenant-set MUST be resolved from the AUTHENTICATED PRINCIPAL by a scope-resolver, never
// from client input — this package enforces the bound but does not decide it.
package fleet

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FleetAlert is a fleet-console alert row. tenant_id is included so the operator sees which tenant owns it.
type FleetAlert struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	Title     string     `json:"title"`
	Severity  string     `json:"severity"`
	Status    string     `json:"status"`
	RiskScore int        `json:"risk_score"`
	Assignee  *uuid.UUID `json:"assignee_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Repository is the operator fleet console's bounded cross-tenant read (seam #1).
type Repository struct{ db *database.DB }

// NewRepository wires the fleet read repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// FleetAlerts reads alerts across the given tenant-set via the fleet_alerts() SECURITY DEFINER function.
// The bound is enforced INSIDE the function (tenant_id = ANY($1); fail-closed on empty/NULL). `tenantIDs`
// MUST already be the principal-resolved scope — this method never widens it. status "" = all statuses;
// limit is hard-capped in the function. Runs under WithSystem (no tenant GUC): the definer function bypasses
// RLS regardless, and this is a deliberate, bounded, audited cross-tenant read (not a single-tenant one).
func (r *Repository) FleetAlerts(ctx context.Context, tenantIDs []uuid.UUID, status string, limit int) ([]FleetAlert, error) {
	out := []FleetAlert{}
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, status, risk_score, assignee_id, created_at
			   FROM fleet_alerts($1, $2, $3)`, tenantIDs, status, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a FleetAlert
			if e := rows.Scan(&a.ID, &a.TenantID, &a.Title, &a.Severity, &a.Status, &a.RiskScore, &a.Assignee, &a.CreatedAt); e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// AlertTargetTenant returns the alert's OWN tenant_id if that tenant is within the given fleet scope, else nil
// (the alert is out of the caller's scope, or does not exist) — via the fleet_alert_tenant() SECURITY DEFINER
// function (mig 0084). This is the write path's target resolution: the target comes from the resource (the
// alert row), never from input, and the scope bound is enforced inside the fn. A nil return MUST be treated as
// "refuse the write" by the caller. `tenantIDs` MUST be the principal-resolved fleet scope.
func (r *Repository) AlertTargetTenant(ctx context.Context, alertID uuid.UUID, tenantIDs []uuid.UUID) (*uuid.UUID, error) {
	var target *uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT fleet_alert_tenant($1, $2)`, alertID, tenantIDs).Scan(&target)
	})
	return target, err
}
