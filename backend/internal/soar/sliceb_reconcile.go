package soar

// §6.11 completion reconciler (D-3) — the worker-side loop that turns a submitted containment's `executed`
// into `confirmed` (the vendor reports it took effect) or `failed` (it did NOT), and surfaces a failed /
// stalled containment so it lands in the SOC's triage queue. It asks the two questions the destructive loop
// turns on: WHOSE action (G-2: only rows we caused are listed) and DID IT HAPPEN (the vendor terminal state).
// The poll is READ-ONLY (a status GET), so it needs no gate/kill-switch/rate-cap — those guard execution.

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
)

// ContainmentAlerter surfaces a failed or stalled containment (owner: BOTH a durable HIGH notification and an
// internal alert that lands in the SOC triage queue). Injected at wiring; nil = log-only. Implementations
// MUST be idempotent per executionID (the reconciler may re-observe a stalled action across ticks).
type ContainmentAlerter interface {
	ContainmentFailed(ctx context.Context, tenantID, executionID uuid.UUID, actionKey, target, status string, stalled bool) error
}

// WithAlerter wires the failed/stalled-containment alerter (reconciler). Returns the supervisor for chaining.
func (s *Supervisor) WithAlerter(a ContainmentAlerter) *Supervisor { s.alerter = a; return s }

// ReconcileOnce polls every executed-but-unconfirmed connector action WE caused (past the grace window) for
// its terminal vendor state and applies the D-3 table: Succeeded → confirmed; Failed/Cancelled/TimeOut →
// flip to `failed` (drops out of reverse) + alert; non-terminal past the stall window → alert (stalled),
// leave the row; not-terminal → retry next tick. A synchronous action (no Confirm) is confirmed on sight.
// Returns (confirmed, failed, stalled) counts.
func (s *Supervisor) ReconcileOnce(ctx context.Context) (confirmed, failed, stalled int, err error) {
	plat, e := s.repo.GetPlatformFlags(ctx)
	if e != nil {
		return 0, 0, 0, e
	}
	grace, stall := plat.ConfirmationGraceSecs, plat.ConfirmationStallSecs
	if grace <= 0 {
		grace = 60
	}
	if stall <= 0 {
		stall = 900
	}
	rows, e := s.repo.unconfirmedExecutions(ctx, grace)
	if e != nil {
		return 0, 0, 0, e
	}
	for i := range rows {
		u := rows[i]
		a, ok := s.actioners.lookup(u.ConnectorKey, u.ActionKey)
		if !ok {
			continue // no actioner registered (dormant); leave for when one is
		}
		// A synchronous action has nothing async to await → confirmed on sight.
		if a.Confirm == nil {
			if s.repo.markConfirmed(ctx, u.TenantID, u.ID, "synchronous") == nil {
				confirmed++
			}
			continue
		}
		if u.ActionID == "" {
			s.maybeStall(ctx, u, stall, "no-action-id", &stalled)
			continue
		}
		var creds []byte
		if s.creds != nil {
			c, ce := s.creds.ConnectorCreds(ctx, u.TenantID, u.ConnectorKey)
			if ce != nil {
				s.warn("reconcile: cred decrypt failed", u, ce)
				continue // transient — retry next tick, do not confirm/fail on missing creds
			}
			creds = c
		}
		done, success, status, ce := safeConfirm(a, ctx, creds, u.ActionID)
		if ce != nil {
			s.warn("reconcile: confirm poll failed", u, ce)
			continue // transient — retry next tick (never confirm/fail on a poll error)
		}
		switch {
		case done && success:
			if s.repo.markConfirmed(ctx, u.TenantID, u.ID, status) == nil {
				confirmed++
			}
		case done && !success:
			if s.repo.markContainmentFailed(ctx, u.TenantID, u.ID, status) == nil {
				failed++
				s.alert(ctx, u, status, false)
			}
		default: // not terminal (Pending/InProgress, or an aged-out NotFound)
			s.maybeStall(ctx, u, stall, status, &stalled)
		}
	}
	return confirmed, failed, stalled, nil
}

// maybeStall alerts (once, deduped by the alerter) when a non-terminal action has outlived the stall window,
// without changing the row (it may still succeed later; the alert flags it for a human).
func (s *Supervisor) maybeStall(ctx context.Context, u unconfirmedExecution, stall int, status string, n *int) {
	if u.AgeSecs > stall {
		s.alert(ctx, u, "stalled:"+status, true)
		*n++
	}
}

func (s *Supervisor) alert(ctx context.Context, u unconfirmedExecution, status string, stalled bool) {
	if s.alerter == nil {
		s.warn("containment "+status+" but no alerter wired", u, nil)
		return
	}
	if e := s.alerter.ContainmentFailed(ctx, u.TenantID, u.ID, u.ActionKey, u.Target, status, stalled); e != nil {
		s.warn("reconcile: alert failed", u, e)
	}
}

func (s *Supervisor) warn(msg string, u unconfirmedExecution, err error) {
	if s.log == nil {
		return
	}
	s.log.Warn(msg, "execution", u.ID, "action", u.ActionKey, "connector", u.ConnectorKey, "err", err)
}

// safeConfirm runs an Actioner's Confirm with panic recovery (a panic becomes an error → retry next tick).
func safeConfirm(a Actioner, ctx context.Context, creds []byte, actionRef string) (done, success bool, status string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &reconcilePanic{r}
		}
	}()
	return a.Confirm(ctx, creds, actionRef)
}

type reconcilePanic struct{ v any }

func (p *reconcilePanic) Error() string { return "confirm panic" }

// StartReconcileLoop drives ReconcileOnce on a ticker until ctx is cancelled (worker crash-recovery-safe,
// panic-guarded). No-op cadence when nothing is unconfirmed. Runs in exactly one process.
func (s *Supervisor) StartReconcileLoop(ctx context.Context, log *slog.Logger, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(log, "soar-reconcile", func() {
				if c, f, st, err := s.ReconcileOnce(ctx); err != nil {
					log.Warn("soar reconcile failed", "err", err)
				} else if c+f+st > 0 {
					log.Info("soar reconcile", "confirmed", c, "failed", f, "stalled", st)
				}
			})
		}
	}
}
