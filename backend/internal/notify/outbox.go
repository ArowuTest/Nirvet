package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/safe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxDeliveryAttempts bounds redelivery: after this many failed sends a row is
// dead-lettered (status='failed') so the dispatcher stops retrying it forever. The
// failure is durable and queryable (last_error), never silently discarded.
const maxDeliveryAttempts = 5

// OutboxItem is one pending outbound notification drained by the dispatcher.
type OutboxItem struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Channel   string
	Recipient string
	Subject   string
	Body      string
	Attempts  int
}

// OutboxRepository persists the durable notification outbox (SRS §6.8/§6.16; R3 delivery
// guarantee). Enqueue happens inside the producer's own tenant tx (so it commits
// atomically with the state change that caused it); the dispatcher drains across tenants.
type OutboxRepository struct{ db *database.DB }

// NewOutboxRepository builds the repository.
func NewOutboxRepository(db *database.DB) *OutboxRepository { return &OutboxRepository{db: db} }

// EnqueueTx inserts a pending notification within an EXISTING tenant transaction. The
// caller's tx must already have the tenant GUC set to tenantID (it does, when called from
// a WithTenant block), so the RLS WITH CHECK passes. Satisfies incident.Enqueuer.
func (r *OutboxRepository) EnqueueTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, channel, recipient, subject, body string) error {
	if channel == "" {
		channel = "log"
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO notification_outbox (id, tenant_id, channel, recipient, subject, body)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.New(), tenantID, channel, recipient, subject, body)
	return err
}

// Enqueue inserts a pending notification in its own tenant transaction — for callers that are not
// already inside a WithTenant block (e.g. the SOAR notify action executor). Prefer EnqueueTx when
// the enqueue must commit atomically with another state change.
func (r *OutboxRepository) Enqueue(ctx context.Context, tenantID uuid.UUID, channel, recipient, subject, body string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return r.EnqueueTx(ctx, tx, tenantID, channel, recipient, subject, body)
	})
}

// pending returns undelivered notifications across all tenants via the SECURITY DEFINER
// drain function (the table is RLS-FORCEd, so a plain WithSystem select would see nothing).
func (r *OutboxRepository) pending(ctx context.Context, limit int) ([]OutboxItem, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var out []OutboxItem
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, channel, recipient, subject, body, attempts FROM notification_outbox_pending($1)`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it OutboxItem
			if err := rows.Scan(&it.ID, &it.TenantID, &it.Channel, &it.Recipient, &it.Subject, &it.Body, &it.Attempts); err != nil {
				return err
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

// markSent flips a delivered row to 'sent' (tenant-scoped; RLS allows own-tenant write).
func (r *OutboxRepository) markSent(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_outbox SET status='sent', sent_at=now() WHERE id=$1`, id)
		return err
	})
}

// markFailed records a failed attempt: increment attempts + store the error, and dead-letter
// to 'failed' once attempts reach the cap (otherwise the row stays 'pending' for retry).
func (r *OutboxRepository) markFailed(ctx context.Context, tenantID, id uuid.UUID, attempts int, errMsg string) error {
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	status := "pending"
	if attempts+1 >= maxDeliveryAttempts {
		status = "failed"
	}
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE notification_outbox SET attempts=attempts+1, last_error=$2, status=$3 WHERE id=$1`,
			id, errMsg, status)
		return err
	})
}

// Drain delivers up to limit pending notifications, marking each sent (on success) or
// failed (on error, with retry/dead-letter). Returns the number delivered. Safe to run on
// every tick and in multiple processes: each row is claimed by its terminal status update.
func (s *Service) Drain(ctx context.Context, limit int) (int, error) {
	if s.outbox == nil {
		return 0, nil
	}
	items, err := s.outbox.pending(ctx, limit)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, it := range items {
		derr := s.Dispatch(ctx, Message{To: it.Recipient, Subject: it.Subject, Body: it.Body, Channel: it.Channel})
		if derr != nil {
			_ = s.outbox.markFailed(ctx, it.TenantID, it.ID, it.Attempts, derr.Error())
			continue
		}
		if err := s.outbox.markSent(ctx, it.TenantID, it.ID); err != nil {
			// Delivered but the status update failed; a later tick will redeliver (at-least-once).
			s.log.Warn("outbox mark-sent failed (will redeliver)", "id", it.ID, "err", err)
			continue
		}
		sent++
	}
	return sent, nil
}

// StartDispatcher drains the outbox on a ticker until ctx is cancelled. Panic-guarded per
// tick (R2 H-E) so one bad delivery cannot kill the loop.
func (s *Service) StartDispatcher(ctx context.Context, log *slog.Logger, interval time.Duration, limit int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe.Do(log, "notification-dispatcher", func() {
				if n, err := s.Drain(ctx, limit); err != nil {
					log.Warn("notification dispatch failed", "err", err)
				} else if n > 0 {
					log.Info("notifications dispatched", "count", n)
				}
			})
		}
	}
}
