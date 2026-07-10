package billing

// §6.17 #126 B-1/B-2 — the metering ledger. Usage is server-derived (RecordUsage is internal — there is NO
// tenant-facing endpoint to assert usage, so a tenant cannot under-report). Each increment is an append-only
// POINT-DELTA with a DB-unique idempotency key, so a replay is a no-op (no double-count) and a distinct real
// increment is never lost. The rollup is always SUM(usage_events) — no mutable counter, so it can never drift.

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Metric is a metered usage dimension (BILL-002).
type Metric string

const (
	MetricLogVolume       Metric = "log_volume"
	MetricAlertCount      Metric = "alert_count"
	MetricReportCount     Metric = "report_count"
	MetricPlaybookActions Metric = "playbook_actions"
	MetricConnectorCount  Metric = "connector_count"
	MetricAssetCount      Metric = "asset_count"
	MetricAPIUsage        Metric = "api_usage"
	MetricStorage         Metric = "storage"
	MetricPSHours         Metric = "ps_hours"
)

// meterRegistry is the code-owned allow-list of metrics. PIN-2: every metric is an append-only POINT-DELTA summed at
// rollup, NEVER a mutable running counter. The idempotency key is the CALLER's deterministic responsibility, one
// distinct key per real increment so a retry of the same increment collides (no double-count) and a genuine new
// increment does not (no loss). Documented key conventions:
//
//	log_volume        → log_volume:<tenant>:<yyyy-mm-dd>   (one delta recorded at day-close)
//	playbook_actions  → playbook_action:<run_id>:<step>     (per occurrence)
//	report_count      → report_count:<report_id>
//	alert_count       → alert_count:<alert_id>
//
// Getting the granularity wrong the other way (a cumulative snapshot re-recorded higher) would be rejected as a
// duplicate and UNDER-count — hence deltas, never snapshots.
var meterRegistry = map[Metric]bool{
	MetricLogVolume: true, MetricAlertCount: true, MetricReportCount: true, MetricPlaybookActions: true,
	MetricConnectorCount: true, MetricAssetCount: true, MetricAPIUsage: true, MetricStorage: true, MetricPSHours: true,
}

// IsMetric reports whether a metric is registered.
func IsMetric(m Metric) bool { return meterRegistry[m] }

func periodOf(t time.Time) string { return t.UTC().Format("2006-01") }

// RecordUsage appends a usage point-delta idempotently. If the event's own period is already CLOSED, the delta is
// recorded against the current OPEN period as an adjustment (PIN-1 record-don't-drop) — never mutating the closed
// invoice, never dropped. Returns whether a NEW event was recorded (false = idempotent no-op on replay).
func (r *Repository) RecordUsage(ctx context.Context, tenantID uuid.UUID, metric Metric, quantity int64, idemKey, source string, occurredAt time.Time) (bool, error) {
	if !meterRegistry[metric] {
		return false, fmt.Errorf("billing: unknown metric %q", metric)
	}
	if quantity < 0 {
		return false, fmt.Errorf("billing: negative usage quantity rejected") // M-3 (also a DB CHECK)
	}
	if idemKey == "" {
		return false, fmt.Errorf("billing: idempotency key required")
	}
	eventPeriod := periodOf(occurredAt)
	billPeriod := eventPeriod
	isAdj := false
	inserted := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var closed bool
		e := tx.QueryRow(ctx, `SELECT status='closed' FROM billing_period WHERE tenant_id=$1 AND period=$2`,
			tenantID, eventPeriod).Scan(&closed)
		if e != nil && e != pgx.ErrNoRows {
			return e // no row → the period isn't closed
		}
		if closed { // PIN-1: adjust a late event forward to the current open period
			billPeriod = periodOf(time.Now())
			isAdj = true
		}
		ct, e := tx.Exec(ctx,
			`INSERT INTO usage_events (tenant_id, metric, quantity, period, event_period, is_adjustment, idempotency_key, source)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id, metric, idempotency_key) DO NOTHING`,
			tenantID, string(metric), quantity, billPeriod, eventPeriod, isAdj, idemKey, source)
		if e != nil {
			return e
		}
		inserted = ct.RowsAffected() == 1
		return nil
	})
	return inserted, err
}

// MetricTotal is a metric's summed usage for a period.
type MetricTotal struct {
	Metric Metric `json:"metric"`
	Total  int64  `json:"total"`
}

// Rollup returns the summed usage per metric for a tenant+period. It is ALWAYS SUM(usage_events) computed on read —
// there is no separate counter to drift (M-5 reconciliation holds by construction).
func (r *Repository) Rollup(ctx context.Context, tenantID uuid.UUID, period string) ([]MetricTotal, error) {
	var out []MetricTotal
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT metric, sum(quantity) FROM usage_events WHERE tenant_id=$1 AND period=$2 GROUP BY metric ORDER BY metric`,
			tenantID, period)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m MetricTotal
			if e := rows.Scan(&m.Metric, &m.Total); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// ClosePeriod marks a billing period closed (the invoice step). Idempotent.
func (r *Repository) ClosePeriod(ctx context.Context, tenantID uuid.UUID, period string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO billing_period (tenant_id, period, status, closed_at) VALUES ($1,$2,'closed',now())
			 ON CONFLICT (tenant_id, period) DO UPDATE SET status='closed', closed_at=now()`, tenantID, period)
		return e
	})
}

// RecordUsage (service) is the internal server-derived metering entry point. It is deliberately NOT exposed on any
// tenant-facing handler — only platform code (report generation, SOAR actions, ingest close) calls it.
func (s *Service) RecordUsage(ctx context.Context, tenantID uuid.UUID, metric Metric, quantity int64, idemKey, source string, occurredAt time.Time) (bool, error) {
	return s.repo.RecordUsage(ctx, tenantID, metric, quantity, idemKey, source, occurredAt)
}

// Rollup (service) returns the metered usage for a tenant+period.
func (s *Service) Rollup(ctx context.Context, tenantID uuid.UUID, period string) ([]MetricTotal, error) {
	return s.repo.Rollup(ctx, tenantID, period)
}

// CurrentPeriod is the current billing period key.
func CurrentPeriod() string { return periodOf(time.Now()) }
