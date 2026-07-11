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
	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Summary is a point-in-time operational report for a tenant.
type Summary struct {
	TenantID         uuid.UUID               `json:"tenant_id"`
	GeneratedAt      time.Time               `json:"generated_at"`
	AlertsBySeverity map[string]int          `json:"alerts_by_severity"`
	OpenAlerts       int                     `json:"open_alerts"`
	IncidentsByStage map[string]int          `json:"incidents_by_stage"`
	OpenIncidents    int                     `json:"open_incidents"`
	EventsLast24h    int                     `json:"events_last_24h"`
	TopMITRE         []eventstore.MITRECount `json:"top_mitre"`  // ATT&CK coverage (v1.1)
	SLA              SLAPosture              `json:"sla"`        // §6.8 SLA posture
	MeanTimes        MeanTimes               `json:"mean_times"` // MTTA/MTTR mean-time KPIs
}

// SLAPosture summarises the tenant's incident SLA health (SRS §6.8).
type SLAPosture struct {
	OpenIncidents    int `json:"open_incidents"`    // not yet closed
	AckBreaching     int `json:"ack_breaching"`     // open, past ack deadline, unacknowledged
	ResolveBreaching int `json:"resolve_breaching"` // open, past resolve deadline
	ResolvedLate     int `json:"resolved_late"`     // closed after the resolve deadline
}

// MeanTimes reports mean-time KPIs over a rolling window (SRS §6.8; Ghana MTTT KPI). Only metrics that are
// correct-by-construction from stored control-plane timestamps are reported here:
//   - MTTA (mean time to acknowledge) = mean(acknowledged_at − created_at) over incidents acknowledged in-window.
//   - MTTR (mean time to resolve)     = mean(closed_at − created_at) over incidents closed in-window.
//
// Values are nil when there are no qualifying incidents (a mean over zero is undefined — never rendered as 0).
// The sample counts are exposed so the UI can caveat a mean drawn from very few incidents.
// NOTE (deferred, by design): MTTC (contain) needs a stage-transition history — no "reached-contained" timestamp
// is stored today; MTTD (detect) needs reliable source event-time (ObservedAt falls back to ingestion time). Both
// are a documented fast-follow rather than a fabricated number.
type MeanTimes struct {
	WindowDays        int      `json:"window_days"`
	MTTASeconds       *float64 `json:"mtta_seconds"`       // nil if no acknowledged incidents in-window
	MTTRSeconds       *float64 `json:"mttr_seconds"`       // nil if no closed incidents in-window
	AcknowledgedCount int      `json:"acknowledged_count"` // sample size behind MTTA
	ResolvedCount     int      `json:"resolved_count"`     // sample size behind MTTR
}

// meanTimeWindowDays is the rolling window for the mean-time KPIs.
const meanTimeWindowDays = 30

// Service computes reports. Alerts/incidents come from the Postgres system of
// record; the event count comes from the EventStore so it is correct on any
// backend (Postgres or ClickHouse — ADR-0002/0006).
type Service struct {
	db     *database.DB
	events eventstore.EventStore
}

// NewService builds the service.
func NewService(db *database.DB, events eventstore.EventStore) *Service {
	return &Service{db: db, events: events}
}

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
		// R6: "open" is defined consistently as closed_at IS NULL (matches the SLA block below). Using
		// stage<>'closed' disagreed for post_incident_review (closed_at set, stage≠closed).
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE closed_at IS NULL`).Scan(&sum.OpenIncidents); err != nil {
			return err
		}
		// SLA posture (§6.8) in one pass over incidents.
		if err := tx.QueryRow(ctx,
			`SELECT
			   count(*) FILTER (WHERE closed_at IS NULL),
			   count(*) FILTER (WHERE closed_at IS NULL AND ack_due_at < now() AND acknowledged_at IS NULL),
			   count(*) FILTER (WHERE closed_at IS NULL AND resolve_due_at < now()),
			   count(*) FILTER (WHERE closed_at IS NOT NULL AND resolve_due_at IS NOT NULL AND closed_at > resolve_due_at)
			 FROM incidents`,
		).Scan(&sum.SLA.OpenIncidents, &sum.SLA.AckBreaching, &sum.SLA.ResolveBreaching, &sum.SLA.ResolvedLate); err != nil {
			return err
		}
		// Mean-time KPIs (MTTA/MTTR) over the rolling window, in one pass over incidents. avg() returns NULL
		// for an empty sample → scanned into *float64 (nil), never a misleading 0. The `>= created_at` guards
		// exclude clock-skew/backfill rows that would yield a negative duration.
		sum.MeanTimes.WindowDays = meanTimeWindowDays
		since := sum.GeneratedAt.Add(-time.Duration(meanTimeWindowDays) * 24 * time.Hour)
		return tx.QueryRow(ctx,
			`SELECT
			   avg(extract(epoch FROM (acknowledged_at - created_at)))
			     FILTER (WHERE acknowledged_at IS NOT NULL AND acknowledged_at >= $1 AND acknowledged_at >= created_at),
			   count(*)
			     FILTER (WHERE acknowledged_at IS NOT NULL AND acknowledged_at >= $1 AND acknowledged_at >= created_at),
			   avg(extract(epoch FROM (closed_at - created_at)))
			     FILTER (WHERE closed_at IS NOT NULL AND closed_at >= $1 AND closed_at >= created_at),
			   count(*)
			     FILTER (WHERE closed_at IS NOT NULL AND closed_at >= $1 AND closed_at >= created_at)
			 FROM incidents`, since,
		).Scan(&sum.MeanTimes.MTTASeconds, &sum.MeanTimes.AcknowledgedCount,
			&sum.MeanTimes.MTTRSeconds, &sum.MeanTimes.ResolvedCount)
	})
	if err != nil {
		return nil, err
	}
	// Event volume comes from the EventStore (Postgres or ClickHouse), not a raw
	// Postgres query — so dashboards are correct whichever telemetry backend is live.
	if s.events != nil {
		since := sum.GeneratedAt.Add(-24 * time.Hour)
		n, cerr := s.events.CountSince(ctx, tenantID, since)
		if cerr != nil {
			return nil, cerr
		}
		sum.EventsLast24h = n
		// ATT&CK coverage over the promoted mitre column (ADR-0006 v1.1).
		top, terr := s.events.TopMITRE(ctx, tenantID, since, 10)
		if terr != nil {
			return nil, terr
		}
		sum.TopMITRE = top
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
