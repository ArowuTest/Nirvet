package billing

// ING-010 / BILL-002 — feed the usage-metering ledger. The ledger (metering.go) and the overage arithmetic
// (invoice.go OverMetrics) were correct but had NO producer: RecordUsage had zero callers, so log_volume was
// never recorded, overage always computed 0, and the "exceeded contracted volume" commercial signal could never
// fire. This is the day-close producer for the ingest-volume metric — the one that drives overage.
//
// Design (matches metering.go's documented "one delta recorded at day-close" comment): for each billable tenant,
// record log_volume = count(raw_events) for a CLOSED UTC day, keyed idempotently by log_volume:<tenant>:<date>.
// Only closed days are metered — a past day's count is final (received_at is stamped at ingest, so no event ever
// lands in a past day), and the ledger is idempotent-by-key (ON CONFLICT DO NOTHING), so re-running a day is a
// no-op. Metering today's PARTIAL count would be wrong: the first (small) delta would win and freeze the day.
//
// NOTE (slice-C, tracked #174): the other metered dimensions (alert_count, report_count, playbook_actions) still
// need producers wired at their emit points; this closes the highest-value + commercially-material one (volume).

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// billableTenantIDs enumerates non-offboarded tenants.
//
// The exclusion list must match the ACTUAL terminal states. It filtered NOT IN ('archived','churned') — but those
// values became IMPOSSIBLE at migration 0073, which replaced the status vocabulary with
// {onboarding,active,suspended,exported,deleted}. So the filter excluded nothing AND failed to exclude the real
// terminal states, meaning offboarded tenants (exported/deleted) kept getting metered — billed after they left.
// Aligned to the real terminals here.
func (r *Repository) billableTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM tenants WHERE status NOT IN ('exported','deleted') ORDER BY id`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		return rows.Err()
	})
	return ids, err
}

// countRawEventsForDay counts a tenant's ingested raw events in [dayStart, dayStart+24h). Runs in the tenant's
// RLS context; the (tenant_id, received_at) index (migration 0053) makes it an index range.
func (r *Repository) countRawEventsForDay(ctx context.Context, tenantID uuid.UUID, dayStart time.Time) (int64, error) {
	end := dayStart.Add(24 * time.Hour)
	var n int64
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE received_at >= $1 AND received_at < $2`,
			dayStart, end).Scan(&n)
	})
	return n, err
}

// MeterDailyIngest records each billable tenant's ingest log_volume for the given (closed) UTC day. Idempotent
// per (tenant, day). A per-tenant error is logged, not fatal — one bad tenant must not stop the rest.
func (s *Service) MeterDailyIngest(ctx context.Context, log *slog.Logger, day time.Time) {
	dayStart := day.UTC().Truncate(24 * time.Hour)
	ids, err := s.repo.billableTenantIDs(ctx)
	if err != nil {
		if log != nil {
			log.Warn("metering: enumerate tenants", "err", err)
		}
		return
	}
	dateKey := dayStart.Format("2006-01-02")
	for _, id := range ids {
		n, err := s.repo.countRawEventsForDay(ctx, id, dayStart)
		if err != nil {
			if log != nil {
				log.Warn("metering: count raw events", "tenant", id, "day", dateKey, "err", err)
			}
			continue
		}
		if n == 0 {
			continue // nothing ingested → no delta (avoids empty rows)
		}
		idem := fmt.Sprintf("log_volume:%s:%s", id, dateKey)
		if _, err := s.RecordUsage(ctx, id, MetricLogVolume, n, idem, "ingest_day_close", dayStart); err != nil {
			if log != nil {
				log.Warn("metering: record log_volume", "tenant", id, "day", dateKey, "err", err)
			}
		}
	}
}

// StartDailyMeteringLoop meters recent CLOSED UTC days' ingest volume on a ticker. It re-meters the last two
// closed days each tick (idempotent) so a missed run across a day boundary self-heals; the cadence only bounds
// staleness, not correctness. Panic-guarded so a bad pass can't take down the worker.
func (s *Service) StartDailyMeteringLoop(ctx context.Context, log *slog.Logger, interval time.Duration) {
	run := func() {
		safe.Do(log, "billing daily metering", func() {
			now := time.Now().UTC()
			s.MeterDailyIngest(ctx, log, now.AddDate(0, 0, -1)) // yesterday (closed)
			s.MeterDailyIngest(ctx, log, now.AddDate(0, 0, -2)) // day-before (covers a missed boundary run)
		})
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
