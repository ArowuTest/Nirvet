// Package postureproj is the vendor-posture PROJECTION choke point (MA-4 population, push-not-pull).
//
// It is the ONE place content is read to produce posture (MA4-1: a single choke point, easy to prove the
// metadata/content line at). It reads incident METADATA (counts, timestamps, the severity enum) and writes
// scalar Metrics into the posture store via posture.Record — which takes scalars only, so no content struct
// can cross. This package is DELIBERATELY separate from internal/posture: the projector is the writer and is
// allowed to touch content; internal/posture (the read+store package) imports no content and is CI-guarded.
// Nothing flows the other way — posture never reads back through here.
package postureproj

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/ArowuTest/nirvet/internal/posture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Recorder is the write side of the posture store the projector calls (scalars only). *posture.Service
// satisfies it. Kept as an interface so the projector doesn't hard-depend on the posture service graph.
type Recorder interface {
	Record(ctx context.Context, tenantID uuid.UUID, m posture.Metrics) error
}

// Projector computes each tenant's posture from incident metadata and records it. atRiskWindow is how far
// ahead of resolve_due_at counts as "at risk".
type Projector struct {
	db           *database.DB
	rec          Recorder
	atRiskWindow time.Duration
}

// NewProjector wires the projector. A zero atRiskWindow defaults to one hour.
func NewProjector(db *database.DB, rec Recorder) *Projector {
	return &Projector{db: db, rec: rec, atRiskWindow: time.Hour}
}

// Project computes and records one tenant's posture. It reads incident METADATA only — counts by the severity
// enum, ack/SLA-clock state from timestamps — and NEVER selects a title/description/category. escalated stays
// 0 in slice A (escalation state lives in the notify domain, #78; joinable in a follow-on — the column is
// present so the store is ready, and the deferral is explicit rather than a silently-empty metric).
func (p *Projector) Project(ctx context.Context, tenantID uuid.UUID) error {
	var m posture.Metrics
	err := p.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT
			  count(*) FILTER (WHERE closed_at IS NULL)                                            AS open_total,
			  count(*) FILTER (WHERE closed_at IS NULL AND severity='critical')                    AS open_critical,
			  count(*) FILTER (WHERE closed_at IS NULL AND severity='high')                        AS open_high,
			  count(*) FILTER (WHERE closed_at IS NULL AND severity='medium')                      AS open_medium,
			  count(*) FILTER (WHERE closed_at IS NULL AND severity='low')                         AS open_low,
			  min(created_at) FILTER (WHERE closed_at IS NULL)                                     AS oldest_open_at,
			  count(*) FILTER (WHERE closed_at IS NULL AND acknowledged_at IS NULL)                AS unacked,
			  count(*) FILTER (WHERE closed_at IS NULL AND acknowledged_at IS NULL
			                        AND ack_due_at IS NOT NULL AND ack_due_at < now())            AS ack_overdue,
			  count(*) FILTER (WHERE closed_at IS NULL AND resolve_due_at IS NOT NULL
			                        AND resolve_due_at < now())                                    AS sla_breached,
			  count(*) FILTER (WHERE closed_at IS NULL AND resolve_due_at IS NOT NULL
			                        AND resolve_due_at >= now() AND resolve_due_at < now() + $1::interval) AS sla_at_risk,
			  max(created_at)                                                                      AS last_activity_at
			FROM incidents`,
			p.atRiskWindow.String(),
		).Scan(&m.OpenTotal, &m.OpenCritical, &m.OpenHigh, &m.OpenMedium, &m.OpenLow, &m.OldestOpenAt,
			&m.Unacked, &m.AckOverdue, &m.SLABreached, &m.SLAAtRisk, &m.LastActivityAt)
	})
	if err != nil {
		return err
	}
	return p.rec.Record(ctx, tenantID, m)
}

// ProjectAll recomputes posture for every tenant in the instance (the refresh driver's unit of work).
func (p *Projector) ProjectAll(ctx context.Context) (int, error) {
	var ids []uuid.UUID
	if err := p.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if err := p.Project(ctx, id); err == nil {
			n++
		}
	}
	return n, nil
}

// StartRefreshLoop periodically re-projects the whole fleet's posture until ctx is cancelled (slice-A
// population driver; on-incident-transition triggering is a documented follow-on). Panic-guarded.
func (p *Projector) StartRefreshLoop(ctx context.Context, log *slog.Logger, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(log, "posture-refresh", func() {
				if n, err := p.ProjectAll(ctx); err != nil {
					log.Warn("posture refresh failed", "err", err)
				} else {
					log.Debug("posture refreshed", "tenants", n)
				}
			})
		}
	}
}
