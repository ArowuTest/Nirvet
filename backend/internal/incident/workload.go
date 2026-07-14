package incident

// Manager team/workload aggregate (UI-depth Bucket B / B4). A per-owner roll-up of OPEN incidents so a SOC lead
// can see who is carrying what and where SLAs are breaching. Read-only, tenant-RLS-scoped, no new table: it
// GROUP BYs the incidents table (LEFT JOIN users for the assignee email so the owner_id-IS-NULL "Unassigned"
// bucket survives). SLA breach is derived in SQL exactly as sla.go derives it on read (mig 0020 — breach is not
// a stored column), so this surface and the at-risk queue agree.

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// WorkloadRow is one assignee's open-incident load. OwnerID is nil for the unassigned bucket.
type WorkloadRow struct {
	OwnerID      *uuid.UUID `json:"owner_id,omitempty"`
	OwnerEmail   string     `json:"owner_email"` // "" when unassigned → UI renders "Unassigned"
	OpenTotal    int        `json:"open_total"`
	OpenCritical int        `json:"open_critical"`
	OpenHigh     int        `json:"open_high"`
	SLABreached  int        `json:"sla_breached"`
	SLAAtRisk    int        `json:"sla_at_risk"`
	OldestOpenAt *time.Time `json:"oldest_open_at,omitempty"`
}

// WorkloadByOwner aggregates open incidents per owner under the tenant's RLS. Breach and at-risk are derived in
// SQL (see sla.go). The 30-minute at-risk window mirrors ListAtRisk so the two surfaces stay consistent.
func (r *Repository) WorkloadByOwner(ctx context.Context, tenantID uuid.UUID) ([]WorkloadRow, error) {
	var out []WorkloadRow
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT i.owner_id, u.email,
			        count(*) AS open_total,
			        count(*) FILTER (WHERE i.severity = 'critical') AS open_critical,
			        count(*) FILTER (WHERE i.severity = 'high')     AS open_high,
			        count(*) FILTER (WHERE
			              (i.ack_due_at IS NOT NULL AND i.acknowledged_at IS NULL AND i.ack_due_at < now())
			           OR (i.resolve_due_at IS NOT NULL AND i.resolve_due_at < now())) AS sla_breached,
			        count(*) FILTER (WHERE
			              NOT ((i.ack_due_at IS NOT NULL AND i.acknowledged_at IS NULL AND i.ack_due_at < now())
			                OR (i.resolve_due_at IS NOT NULL AND i.resolve_due_at < now()))
			          AND ((i.ack_due_at IS NOT NULL AND i.acknowledged_at IS NULL AND i.ack_due_at < now() + interval '30 minutes')
			                OR (i.resolve_due_at IS NOT NULL AND i.resolve_due_at < now() + interval '30 minutes'))) AS sla_at_risk,
			        min(i.created_at) AS oldest_open_at
			   FROM incidents i
			   LEFT JOIN users u ON u.id = i.owner_id
			  WHERE i.closed_at IS NULL
			  GROUP BY i.owner_id, u.email
			  ORDER BY sla_breached DESC, open_total DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w WorkloadRow
			var email *string
			if err := rows.Scan(&w.OwnerID, &email, &w.OpenTotal, &w.OpenCritical, &w.OpenHigh,
				&w.SLABreached, &w.SLAAtRisk, &w.OldestOpenAt); err != nil {
				return err
			}
			if email != nil {
				w.OwnerEmail = *email
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}

// Workload returns the per-owner open-incident aggregate for the tenant (thin passthrough — ordering + derivation
// happen in SQL).
func (s *Service) Workload(ctx context.Context, tenantID uuid.UUID) ([]WorkloadRow, error) {
	return s.repo.WorkloadByOwner(ctx, tenantID)
}

// Workload handles GET /incidents/workload — the manager team-load roll-up.
func (h *Handler) Workload(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	rows, err := h.svc.Workload(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"workload": rows})
}
