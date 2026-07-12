package connector

// #188 LAUNCH #5 (LIGHT) — connector credential-expiry reminder. A pull connector's OAuth secret / API key expires
// on the customer's schedule; when it lapses ingestion silently stops. An admin records the credential's expiry
// (SetCredExpiry) and a panic-guarded provider sweeper reminds the tenant's escalation contacts once, before it
// lapses. This MIRRORS the incident SLA-breach sweeper exactly (the platform's established durable-notify pattern):
// a SECURITY DEFINER cross-tenant read (connectors_expiring), per-tenant escalation-matrix routing, and a
// claim-then-enqueue in ONE tenant tx so the reminder is exactly-once AND delivery is durable (outbox retry).

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/incident"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// credExpiryReminderLead is how far AHEAD of expiry to remind — an operational cadence constant like the other
	// sweeper intervals (NOT tenant policy). 14 days gives an admin time to rotate the credential before it lapses.
	credExpiryReminderLead  = 14 * 24 * time.Hour
	credExpirySweepInterval = 6 * time.Hour
	credExpirySweepLimit    = 500
)

// CredEnqueuer durably queues a reminder on the notify outbox within the caller's tx (implemented by
// notify.OutboxRepository). Narrow so connector does not depend on the notify package.
type CredEnqueuer interface {
	EnqueueTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, channel, recipient, subject, body string) error
}

// CredEscalationResolver returns the tenant escalation-matrix contacts for a severity (implemented by
// tenant.Service — the same resolver the incident SLA sweeper uses). Empty ⇒ fall back to the log channel.
type CredEscalationResolver interface {
	ResolveEscalation(ctx context.Context, tenantID uuid.UUID, severity string) ([]incident.EscalationTarget, error)
}

// WithEscalation wires the escalation-matrix resolver (tenant.Service). Chainable.
func (s *Service) WithEscalation(r CredEscalationResolver) *Service { s.escalation = r; return s }

// WithEnqueuer wires the durable notify outbox. Chainable.
func (s *Service) WithEnqueuer(e CredEnqueuer) *Service { s.enqueuer = e; return s }

// ExpiringCred is one connector whose credential is at/near expiry (a sweeper row).
type ExpiringCred struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Name      string
	Kind      string
	ExpiresAt time.Time
}

// SetCredExpiry records (or clears, with nil) a connector's credential expiry and RESETS the reminder marker so a
// renewed-then-re-expiring credential is reminded again. Tenant-owned only (RLS + the id filter). found=false if
// the connector is not in this tenant.
func (s *Service) SetCredExpiry(ctx context.Context, tenantID, id uuid.UUID, expiresAt *time.Time) error {
	found, err := s.repo.SetCredExpiry(ctx, tenantID, id, expiresAt)
	if err != nil {
		return httpx.ErrInternal("could not set credential expiry")
	}
	if !found {
		return httpx.ErrNotFound("connector not found")
	}
	return nil
}

// SweepCredExpiry finds connectors whose credential expires within the reminder window and reminds each tenant's
// escalation contacts exactly once. Mirrors incident.SweepSLABreaches: system-scoped find, per-tenant resolve +
// claim-then-enqueue atomically. Returns the number reminded.
func (s *Service) SweepCredExpiry(ctx context.Context, now time.Time, limit int) (int, error) {
	rows, err := s.repo.FindExpiringCredentials(ctx, now.Add(credExpiryReminderLead), limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range rows {
		subject := fmt.Sprintf("Connector credential expiring: %s", c.Name)
		body := fmt.Sprintf("The credential for connector '%s' (%s) expires at %s. Rotate it before then to avoid an ingestion outage.",
			c.Name, c.Kind, c.ExpiresAt.UTC().Format(time.RFC3339))
		// Route to the escalation matrix (best-effort). A credential lapse blinds monitoring, so it routes at
		// "high"; no matrix / no resolver ⇒ a single log-channel row so a reminder is never silently unsent.
		var targets []incident.EscalationTarget
		if s.escalation != nil {
			if t, terr := s.escalation.ResolveEscalation(ctx, c.TenantID, "high"); terr == nil {
				targets = t
			}
		}
		tenantID := c.TenantID
		onClaim := func(ctx context.Context, tx pgx.Tx) error {
			if s.enqueuer == nil {
				return nil // no outbox wired (unit path) — the claim still marks it reminded
			}
			if len(targets) == 0 {
				return s.enqueuer.EnqueueTx(ctx, tx, tenantID, "log", "", subject, body)
			}
			for _, t := range targets {
				if e := s.enqueuer.EnqueueTx(ctx, tx, tenantID, t.Channel, t.Address, subject, body); e != nil {
					return e
				}
			}
			return nil
		}
		claimed, cerr := s.repo.ClaimCredExpiryTx(ctx, tenantID, c.ID, onClaim)
		if cerr != nil {
			// Transient error — the claim marker rolled back with the tx, so the next sweep retries this connector.
			continue
		}
		if claimed {
			n++
		}
	}
	return n, nil
}

// StartCredExpiryReaper sweeps credential expiries on a ticker until ctx is cancelled. Panic-guarded so a bad
// sweep can't take down the process (matches the other background loops, e.g. detEngine.StartWindowReaper).
func (s *Service) StartCredExpiryReaper(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(credExpirySweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if rec := recover(); rec != nil && log != nil {
						log.Error("connector cred-expiry reaper panic", "recovered", rec)
					}
				}()
				if n, err := s.SweepCredExpiry(ctx, time.Now(), credExpirySweepLimit); err != nil && log != nil {
					log.Error("connector cred-expiry sweep failed", "err", err)
				} else if n > 0 && log != nil {
					log.Info("connector cred-expiry reminders sent", "count", n)
				}
			}()
		}
	}
}

// ── Repository ───────────────────────────────────────────────────────────────────────────────────────────

// SetCredExpiry updates a tenant connector's cred_expires_at and resets the reminder marker (so a new expiry is
// reminded again). found=false if the id is not a connector in this tenant.
func (r *Repository) SetCredExpiry(ctx context.Context, tenantID, id uuid.UUID, expiresAt *time.Time) (bool, error) {
	found := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE connector_configs SET cred_expires_at = $2, cred_expiry_notified_at = NULL WHERE id = $1`,
			id, expiresAt)
		if e != nil {
			return e
		}
		found = ct.RowsAffected() == 1
		return nil
	})
	return found, err
}

// FindExpiringCredentials returns connectors (across tenants) whose credential expires at/before p_before and
// hasn't been reminded — via the SECURITY DEFINER connectors_expiring fn (connector_configs is RLS FORCEd, so a
// plain WithSystem SELECT would return nothing).
func (r *Repository) FindExpiringCredentials(ctx context.Context, before time.Time, limit int) ([]ExpiringCred, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	var out []ExpiringCred
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, name, kind, cred_expires_at FROM connectors_expiring($1, $2)`, before, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ExpiringCred
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Kind, &c.ExpiresAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ClaimCredExpiryTx atomically claims a connector's expiry reminder (the conditional marker elects exactly one
// winning sweeper) and, ONLY for the winner, runs onClaim (durably enqueues the reminder) in the SAME tenant tx —
// so the outbox row commits with the claim and a transient notifier failure can never drop the reminder. A lost
// claim returns (false, nil).
func (r *Repository) ClaimCredExpiryTx(ctx context.Context, tenantID, id uuid.UUID, onClaim func(ctx context.Context, tx pgx.Tx) error) (bool, error) {
	claimed := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE connector_configs SET cred_expiry_notified_at = now() WHERE id = $1 AND cred_expiry_notified_at IS NULL`, id)
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return nil // another sweeper claimed it first
		}
		claimed = true
		if onClaim != nil {
			return onClaim(ctx, tx)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return claimed, nil
}
