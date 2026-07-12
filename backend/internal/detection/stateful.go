package detection

// DET-002 stateful detection (LAUNCH #2). Threshold ("N contributing events for one entity in a window") and
// distinct ("N distinct values of a field for one entity in a window") rule kinds, on top of the single-event
// engine. The window/threshold are per-rule admin config (detection-as-code); the windowed count lives in
// detection_windows; a rule fires ONCE per (entity, window) via a fired_at latch claimed with a conditional
// UPDATE under the ON-CONFLICT row lock — so two workers crossing the threshold on the same tick fire exactly
// one alert (the double-fire guard).

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/eventstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Engine safety bounds — NOT business policy (window/threshold are per-rule admin config). Like the poller's
// fixed page cap, these bound pathological growth; a rule's own threshold is validated below this cap so the
// backstop can never prevent a legitimate fire.
const (
	maxDistinctPerWindow = 1000          // stop tracking members past this per window (flood backstop)
	maxWindowSeconds     = 7 * 24 * 3600 // upper bound on a rule's window (7 days) — bounds state retention
	windowReaperGrace    = time.Hour     // keep a window this long past its end before the reaper purges it
	windowReaperInterval = 10 * time.Minute
)

// WithLogger attaches a logger for stateful-eval + reaper diagnostics (nil-safe; optional, keeps NewEngine's
// signature unchanged for existing callers).
func (e *Engine) WithLogger(log *slog.Logger) *Engine { e.log = log; return e }

// EvaluateStateful advances the windowed state for every stateful rule whose base condition matches ev and
// returns a Match for each rule that FIRES on this event. Kept separate from Evaluate so the pure single-event
// path stays read-only + unit-testable; the worker calls both. A stateful rule with no entity key on this event
// contributes nothing.
func (e *Engine) EvaluateStateful(ctx context.Context, tenantID uuid.UUID, ev eventstore.NormalizedEvent) ([]Match, error) {
	rules, err := e.rulesFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var matches []Match
	for _, r := range rules {
		if !r.IsStateful() || r.WindowSeconds <= 0 || r.Threshold <= 0 || r.EntityField == "" {
			continue
		}
		if !e.baseMatch(r, ev) {
			continue // this event doesn't contribute to the rule
		}
		entity := fieldValue(ev, r.EntityField)
		if entity == "" {
			continue // no grouping key on this event → can't attribute it to an entity
		}
		when := ev.ObservedAt
		if when.IsZero() {
			when = time.Now()
		}
		windowStart := when.UTC().Truncate(time.Duration(r.WindowSeconds) * time.Second)

		// The counted MEMBER: for a threshold rule it's this event's id (so an event counts at most once, even on
		// a worker retry); for a distinct rule it's the distinct field's value.
		var member string
		switch r.Kind {
		case KindThreshold:
			member = ev.ID.String()
		case KindDistinct:
			member = fieldValue(ev, r.DistinctField)
			if member == "" {
				continue
			}
		}
		fired, err := e.repo.RecordMember(ctx, tenantID, r.ID, entity, windowStart, r.WindowSeconds, member, r.Threshold)
		if err != nil {
			// No silent loss: log and continue. The event's single-event matches (from Evaluate) still fire, and
			// the window row is durable so the next contributing event retries the threshold.
			if e.log != nil {
				e.log.Warn("detection: stateful eval failed", "rule", r.ID, "err", err)
			}
			continue
		}
		if fired {
			matches = append(matches, Match{RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, Confidence: r.Confidence, MITRE: r.MITRE})
		}
	}
	return matches, nil
}

// baseMatch is the per-event contribution test (CEL or Condition), shared with the single-event path.
func (e *Engine) baseMatch(r Rule, ev eventstore.NormalizedEvent) bool {
	if r.Expression != "" {
		if prog := e.programFor(r.Expression); prog != nil {
			return EvalCEL(prog, ev)
		}
		return false
	}
	return r.Condition.Matches(ev)
}

// RecordMember records one member of a (rule, entity, window) — for a threshold rule the member is the
// contributing event's id; for a distinct rule the member is the distinct field value — and fires ONCE when the
// window's member count reaches the threshold. IDEMPOTENT on the member (INSERT … ON CONFLICT DO NOTHING) so a
// retried worker job never double-counts. Concurrency-safe: the window-header ON CONFLICT DO UPDATE takes the row
// lock, serialising the count read + fire-claim, and the fired_at latch (RowsAffected==1) means exactly one call
// ever fires. Members are hard-capped at maxDistinctPerWindow (flood backstop; a rule's threshold is validated
// below the cap so it can never block a legitimate fire). Once fired, tracking stops (bounds growth).
func (r *Repository) RecordMember(ctx context.Context, tenantID, ruleID uuid.UUID, entity string, windowStart time.Time, windowSeconds int, member string, threshold int) (bool, error) {
	fired := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id uuid.UUID
		var firedAt *time.Time
		if err := tx.QueryRow(ctx,
			`INSERT INTO detection_windows (tenant_id, rule_id, entity_key, window_start, window_seconds)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (tenant_id, rule_id, entity_key, window_start)
			 DO UPDATE SET window_seconds = EXCLUDED.window_seconds
			 RETURNING id, fired_at`,
			tenantID, ruleID, entity, windowStart, windowSeconds).Scan(&id, &firedAt); err != nil {
			return err
		}
		if firedAt != nil {
			return nil // already fired this window; stop tracking
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM detection_window_values WHERE tenant_id=$1 AND window_id=$2`, tenantID, id).Scan(&count); err != nil {
			return err
		}
		if count < maxDistinctPerWindow {
			if _, err := tx.Exec(ctx,
				`INSERT INTO detection_window_values (tenant_id, window_id, value) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
				tenantID, id, member); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM detection_window_values WHERE tenant_id=$1 AND window_id=$2`, tenantID, id).Scan(&count); err != nil {
				return err
			}
		}
		if count >= threshold {
			ct, err := tx.Exec(ctx, `UPDATE detection_windows SET fired_at = now() WHERE id=$1 AND fired_at IS NULL`, id)
			if err != nil {
				return err
			}
			fired = ct.RowsAffected() == 1
		}
		return nil
	})
	return fired, err
}

// PurgeExpiredWindows deletes windows past their end + grace across all tenants via the SECURITY DEFINER reaper
// (RLS blocks a no-tenant DELETE). Returns the number deleted.
func (r *Repository) PurgeExpiredWindows(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT detection_purge_expired_windows($1)`, windowReaperGrace).Scan(&n)
	})
	return n, err
}

// StartWindowReaper purges expired detection windows on a ticker until ctx is cancelled. Panic-guarded so a bad
// sweep can't take down the process (matches the other background loops).
func (e *Engine) StartWindowReaper(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(windowReaperInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if rec := recover(); rec != nil && log != nil {
						log.Error("detection window reaper panic", "recovered", rec)
					}
				}()
				if n, err := e.repo.PurgeExpiredWindows(ctx); err != nil && log != nil {
					log.Error("detection window reaper failed", "err", err)
				} else if n > 0 && log != nil {
					log.Info("detection window reaper purged", "count", n)
				}
			}()
		}
	}
}
