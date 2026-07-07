// Package reporting produces customer/executive summaries and evidence (SRS §6.13)
// by aggregating the tenant's own data. Scaffold renders JSON; production adds
// templated PDF/evidence-pack export.
package reporting

import (
	"context"
	"net/http"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Summary is a point-in-time operational report for a tenant.
type Summary struct {
	TenantID         uuid.UUID      `json:"tenant_id"`
	GeneratedAt      time.Time      `json:"generated_at"`
	AlertsBySeverity map[string]int `json:"alerts_by_severity"`
	OpenAlerts       int            `json:"open_alerts"`
	IncidentsByStage map[string]int `json:"incidents_by_stage"`
	OpenIncidents    int            `json:"open_incidents"`
	EventsLast24h    int            `json:"events_last_24h"`
}

// Service computes reports.
type Service struct{ db *database.DB }

// NewService builds the service.
func NewService(db *database.DB) *Service { return &Service{db: db} }

// GeneratedAt is injected (Date.now unavailable in some contexts); here it's the
// server clock, which is valid for a normal service.
func (s *Service) Summary(ctx context.Context, tenantID uuid.UUID) (*Summary, error) {
	sum := &Summary{TenantID: tenantID, GeneratedAt: time.Now(), AlertsBySeverity: map[string]int{}, IncidentsByStage: map[string]int{}}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := scanCounts(ctx, tx, `SELECT severity, count(*) FROM alerts GROUP BY severity`, sum.AlertsBySeverity); err != nil {
			return err
		}
		if err := scanCounts(ctx, tx, `SELECT stage, count(*) FROM incidents GROUP BY stage`, sum.IncidentsByStage); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE status IN ('new','assigned')`).Scan(&sum.OpenAlerts); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE stage <> 'closed'`).Scan(&sum.OpenIncidents); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE observed_at >= now() - interval '24 hours'`).Scan(&sum.EventsLast24h)
	})
	if err != nil {
		return nil, err
	}
	return sum, nil
}

func scanCounts(ctx context.Context, tx pgx.Tx, q string, dst map[string]int) error {
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		dst[k] = n
	}
	return rows.Err()
}

// Handler exposes reporting endpoints.
type Handler struct{ svc *Service }

// NewHandler builds the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// SummaryHTTP handles GET /reports/summary.
func (h *Handler) SummaryHTTP(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	sum, err := h.svc.Summary(r.Context(), p.TenantID)
	if err != nil {
		httpx.Error(w, httpx.ErrInternal("could not generate report"))
		return
	}
	httpx.JSON(w, http.StatusOK, sum)
}
