// Package posture is the vendor POSTURE oversight store (Ghana operator seam #4, MA-4).
//
// It is the metadata-only projection that lets the vendor spot a neglected major issue and flag/escalate
// WITHOUT a standing content read. Its entire security value is STRUCTURAL, and this package is the thing the
// structure protects:
//
//	MA-4 no-import-path invariant: this package imports NO content package — not alert, detection, incident,
//	investigation, nor any event/normalization/telemetry-ingest package. Its repository reads only the
//	`tenant_posture` table (metadata scalars). Content is UNREACHABLE from the posture read path by
//	construction, enforced by scripts/check-posture-no-content-import.sh (go list -deps must not reach content).
//
// Population is push, not pull: the projector (internal/postureproj, the single choke point — allowed to read
// content) computes scalar counts and calls Record with a Metrics of scalars only (MA4-1 — never a content
// struct). Content, when genuinely needed for a disputed claim, is reached ONLY via the sibling §6.2 PAM
// data-owner-visible break-glass — never a link-through from posture.
package posture

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Metrics is the metadata-only posture projection for one tenant — the ONLY shape written into the store.
// Every field is a scalar count/age/timestamp (MA4-1): there is no content struct, no title, no category, no
// telemetry. The projector fills these from incident METADATA; the store has nowhere to put anything else.
type Metrics struct {
	OpenTotal      int        `json:"open_total"`
	OpenCritical   int        `json:"open_critical"`
	OpenHigh       int        `json:"open_high"`
	OpenMedium     int        `json:"open_medium"`
	OpenLow        int        `json:"open_low"`
	OldestOpenAt   *time.Time `json:"oldest_open_at,omitempty"`
	Unacked        int        `json:"unacked"`
	AckOverdue     int        `json:"ack_overdue"`
	SLABreached    int        `json:"sla_breached"`
	SLAAtRisk      int        `json:"sla_at_risk"`
	Escalated      int        `json:"escalated"`
	LastActivityAt *time.Time `json:"last_activity_at,omitempty"`
}

// Posture is a tenant's posture row as read by the vendor oversight surface: the tenant id + its metadata.
type Posture struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Metrics             // embedded scalar metrics
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository is the posture store's data access — it touches ONLY the tenant_posture table (never content).
type Repository struct{ db *database.DB }

// NewRepository builds the posture repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Upsert writes a tenant's posture projection (metadata scalars only), under that tenant's RLS.
func (r *Repository) Upsert(ctx context.Context, tenantID uuid.UUID, m Metrics) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenant_posture (tenant_id, open_total, open_critical, open_high, open_medium, open_low,
			    oldest_open_at, unacked, ack_overdue, sla_breached, sla_at_risk, escalated, last_activity_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
			    open_total=EXCLUDED.open_total, open_critical=EXCLUDED.open_critical, open_high=EXCLUDED.open_high,
			    open_medium=EXCLUDED.open_medium, open_low=EXCLUDED.open_low, oldest_open_at=EXCLUDED.oldest_open_at,
			    unacked=EXCLUDED.unacked, ack_overdue=EXCLUDED.ack_overdue, sla_breached=EXCLUDED.sla_breached,
			    sla_at_risk=EXCLUDED.sla_at_risk, escalated=EXCLUDED.escalated,
			    last_activity_at=EXCLUDED.last_activity_at, updated_at=now()`,
			tenantID, m.OpenTotal, m.OpenCritical, m.OpenHigh, m.OpenMedium, m.OpenLow, m.OldestOpenAt,
			m.Unacked, m.AckOverdue, m.SLABreached, m.SLAAtRisk, m.Escalated, m.LastActivityAt)
		return err
	})
}

// FleetPosture returns the posture rows for the given tenant-set via the MA4-2 dedicated SECURITY DEFINER
// function tenant_posture_fleet() — which reads ONLY tenant_posture (never a content table). Read under
// WithSystem (nirvet_app, non-BYPASSRLS, no tenant GUC): a direct tenant_posture read would return 0 rows, so
// the cross-tenant projection is reachable ONLY through the fail-closed, bound-array SD function.
func (r *Repository) FleetPosture(ctx context.Context, tenantIDs []uuid.UUID) ([]Posture, error) {
	var out []Posture
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, open_total, open_critical, open_high, open_medium, open_low, oldest_open_at,
			       unacked, ack_overdue, sla_breached, sla_at_risk, escalated, last_activity_at, updated_at
			  FROM tenant_posture_fleet($1)`, tenantIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Posture
			if err := rows.Scan(&p.TenantID, &p.OpenTotal, &p.OpenCritical, &p.OpenHigh, &p.OpenMedium,
				&p.OpenLow, &p.OldestOpenAt, &p.Unacked, &p.AckOverdue, &p.SLABreached, &p.SLAAtRisk,
				&p.Escalated, &p.LastActivityAt, &p.UpdatedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
