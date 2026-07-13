// Package retention enforces per-tenant telemetry retention (§6.14 #188 HEAVY-3) — the ONLY feature that DELETES
// customer data. Every design choice fails SAFE toward keeping: legal-hold skips deletion outright; a missing/zero
// retention window keeps; a disabled policy only dry-runs (counts, never deletes); deletion runs in bounded
// batches and a batch error aborts that tenant's sweep (partial keep, never over-delete). It deletes ONLY raw
// telemetry — raw_events (and its blob_uri payload blob in the object store) + the normalized `events` projection —
// never alerts/incidents/evidence/audit. ClickHouse ages out via its own TTL (#160): one owner per store.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// batchSize bounds each delete batch so a sweep never holds a long transaction or a huge lock.
const batchSize = 5000

// Service enforces retention. blobs is the object store for raw payload blobs (best-effort delete with the row).
type Service struct {
	db    *database.DB
	blobs blobstore.Store
}

// NewService builds the retention service.
func NewService(db *database.DB, blobs blobstore.Store) *Service {
	return &Service{db: db, blobs: blobs}
}

// Policy is the tenant-facing view.
type Policy struct {
	Enabled         bool `json:"enabled"`
	WindowDays      *int `json:"window_days,omitempty"` // nil = use the entitlement window
	EffectiveDays   int  `json:"effective_days"`        // resolved effective window (0 = none → keep)
	EntitlementDays int  `json:"entitlement_days"`
}

// resolveWindow returns the tenant's effective retention window and whether deletion is enabled. ok=false means
// there is no usable window (missing/zero entitlement) → the caller KEEPS everything. window = min(policy override,
// entitlement) — the entitlement is the ceiling; a tenant may only TIGHTEN (keep for less), never extend.
func (s *Service) resolveWindow(ctx context.Context, tenantID uuid.UUID) (enabled bool, windowDays, entDays int, ok bool) {
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var override *int
		_ = tx.QueryRow(ctx,
			`SELECT enabled, window_days FROM retention_policy WHERE tenant_id=$1 OR tenant_id IS NULL
			  ORDER BY tenant_id NULLS LAST LIMIT 1`, tenantID).Scan(&enabled, &override)
		if e := tx.QueryRow(ctx, `SELECT retention_days FROM entitlements WHERE tenant_id=$1`, tenantID).Scan(&entDays); e != nil {
			entDays = 0
		}
		windowDays = entDays
		if override != nil && *override > 0 && *override < windowDays {
			windowDays = *override // tighten-only
		}
		return nil
	})
	if entDays <= 0 || windowDays <= 0 {
		return enabled, 0, entDays, false // fail-safe: no usable window → KEEP
	}
	return enabled, windowDays, entDays, true
}

// heldOrMissing reports whether the tenant is on legal hold (preservation wins) or unreadable (fail-safe skip).
func (s *Service) heldOrMissing(ctx context.Context, tenantID uuid.UUID) bool {
	held := true // fail-safe: if we can't read the tenant, treat as held (do not delete)
	_ = s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var lh bool
		var status string
		if e := tx.QueryRow(ctx, `SELECT legal_hold, status FROM tenants WHERE id=$1`, tenantID).Scan(&lh, &status); e != nil {
			return nil // held stays true
		}
		held = lh || status == "legal_hold"
		return nil
	})
	return held
}

// SweepTenant runs one retention pass for a tenant. Order: legal-hold FIRST → resolve window (keep if none) →
// dry-run count (disabled) OR bounded delete (enabled). Returns the number of rows deleted (0 on skip/dry-run).
func (s *Service) SweepTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	if s.heldOrMissing(ctx, tenantID) {
		return 0, nil // legal hold / unreadable → preserve, never delete
	}
	enabled, windowDays, _, ok := s.resolveWindow(ctx, tenantID)
	if !ok {
		return 0, nil // no usable window → keep
	}
	cutoff := time.Now().Add(-time.Duration(windowDays) * 24 * time.Hour)

	if !enabled {
		// Dry-run: count what WOULD be deleted, log it, delete NOTHING.
		var rawN, evN int64
		_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE received_at < $1`, cutoff).Scan(&rawN)
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE collected_at < $1`, cutoff).Scan(&evN)
			return nil
		})
		s.writeLog(ctx, tenantID, "raw_events", cutoff, rawN, 0, true)
		s.writeLog(ctx, tenantID, "events", cutoff, evN, 0, true)
		return 0, nil
	}

	// Enabled: delete raw_events (+ their payload blobs) then events, in bounded batches. A batch error aborts the
	// sweep (partial keep) — under-delete-never-over.
	rawDeleted, err := s.deleteRawEvents(ctx, tenantID, cutoff)
	if err != nil {
		return rawDeleted, err
	}
	evDeleted, err := s.deleteEvents(ctx, tenantID, cutoff)
	if err != nil {
		return rawDeleted + evDeleted, err
	}
	s.writeLog(ctx, tenantID, "raw_events", cutoff, int64(rawDeleted), int64(rawDeleted), false)
	s.writeLog(ctx, tenantID, "events", cutoff, int64(evDeleted), int64(evDeleted), false)
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorEmail: "system:retention", Action: "retention.sweep",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"raw_deleted": rawDeleted, "events_deleted": evDeleted, "cutoff": cutoff.UTC()}})
	})
	return rawDeleted + evDeleted, nil
}

// deleteRawEvents deletes raw_events older than cutoff in batches, deleting each row's payload blob FIRST so the
// blob is never orphaned. A row whose blob delete fails is left for the next sweep (row+blob stay together).
func (s *Service) deleteRawEvents(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int, error) {
	total := 0
	for {
		type cand struct {
			id   uuid.UUID
			blob string
		}
		var batch []cand
		if err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			rows, e := tx.Query(ctx, `SELECT id, COALESCE(blob_uri,'') FROM raw_events WHERE received_at < $1 ORDER BY received_at LIMIT $2`, cutoff, batchSize)
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var c cand
				if e := rows.Scan(&c.id, &c.blob); e != nil {
					return e
				}
				batch = append(batch, c)
			}
			return rows.Err()
		}); err != nil {
			return total, err
		}
		if len(batch) == 0 {
			return total, nil
		}
		// Delete blobs first; only rows whose blob is gone (or had none) are eligible to delete.
		var ids []uuid.UUID
		for _, c := range batch {
			if c.blob != "" {
				if e := s.blobs.Delete(ctx, c.blob); e != nil {
					continue // keep this row+blob together; retry next sweep
				}
			}
			ids = append(ids, c.id)
		}
		if len(ids) == 0 {
			return total, nil // nothing safely deletable this pass
		}
		var n int
		if err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			// Controlled evidence deletion via the fenced SECURITY DEFINER path (disables the immutability trigger
			// for this governed retention sweep only; refuses on legal_hold defense-in-depth).
			return tx.QueryRow(ctx, `SELECT retention_delete_raw($1, $2)`, tenantID, ids).Scan(&n)
		}); err != nil {
			return total, err
		}
		total += n
		if len(batch) < batchSize {
			return total, nil
		}
	}
}

// deleteEvents deletes normalized events older than cutoff in batches (no blob).
func (s *Service) deleteEvents(ctx context.Context, tenantID uuid.UUID, cutoff time.Time) (int, error) {
	total := 0
	for {
		var n int
		if err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT retention_delete_events($1, $2, $3)`, tenantID, cutoff, batchSize).Scan(&n)
		}); err != nil {
			return total, err
		}
		total += n
		if n < batchSize {
			return total, nil
		}
	}
}

func (s *Service) writeLog(ctx context.Context, tenantID uuid.UUID, store string, cutoff time.Time, candidate, deleted int64, dryRun bool) {
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO retention_sweep_log (tenant_id, store, cutoff, candidate_count, deleted_count, dry_run) VALUES ($1,$2,$3,$4,$5,$6)`,
			tenantID, store, cutoff, candidate, deleted, dryRun)
		return e
	})
}

// SweepAll enumerates tenants and sweeps each (a per-tenant error is logged, not fatal — one bad tenant must not
// stop the rest).
func (s *Service) SweepAll(ctx context.Context, log *slog.Logger) {
	var ids []uuid.UUID
	_ = s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM tenants WHERE status NOT IN ('archived','churned') ORDER BY id`)
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
	for _, id := range ids {
		if _, err := s.SweepTenant(ctx, id); err != nil && log != nil {
			log.Warn("retention sweep failed", "tenant", id, "err", err)
		}
	}
}

// StartRetentionReaper runs SweepAll on a ticker until ctx is cancelled. Panic-guarded so a bad sweep can't take
// down the worker.
func (s *Service) StartRetentionReaper(ctx context.Context, log *slog.Logger, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if rec := recover(); rec != nil && log != nil {
						log.Error("retention reaper panic", "recover", rec)
					}
				}()
				s.SweepAll(ctx, log)
			}()
		}
	}
}

// GetPolicy returns the tenant's effective retention view.
func (s *Service) GetPolicy(ctx context.Context, p auth.Principal) Policy {
	enabled, window, ent, ok := s.resolveWindow(ctx, p.TenantID)
	eff := window
	if !ok {
		eff = 0
	}
	var override *int
	_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT window_days FROM retention_policy WHERE tenant_id=$1`, p.TenantID).Scan(&override)
	})
	return Policy{Enabled: enabled, WindowDays: override, EffectiveDays: eff, EntitlementDays: ent}
}

// SetPolicy upserts the tenant's own retention policy (enabled + optional tighten-only window). Audited.
func (s *Service) SetPolicy(ctx context.Context, p auth.Principal, enabled bool, windowDays *int) (Policy, error) {
	if windowDays != nil && (*windowDays < 1 || *windowDays > 3650) {
		return Policy{}, httpx.ErrBadRequest("window_days must be 1..3650 or null")
	}
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO retention_policy (tenant_id, enabled, window_days) VALUES ($1,$2,$3)
			 ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
			 DO UPDATE SET enabled=EXCLUDED.enabled, window_days=EXCLUDED.window_days, updated_at=now()`,
			p.TenantID, enabled, windowDays); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email, Action: "retention.set_policy",
			Target: "tenant:" + p.TenantID.String(), Metadata: map[string]any{"enabled": enabled}})
	})
	if err != nil {
		return Policy{}, err
	}
	return s.GetPolicy(ctx, p), nil
}

// SweepRow is one sweep-log entry.
type SweepRow struct {
	Store          string    `json:"store"`
	Cutoff         time.Time `json:"cutoff"`
	CandidateCount int64     `json:"candidate_count"`
	DeletedCount   int64     `json:"deleted_count"`
	DryRun         bool      `json:"dry_run"`
	At             time.Time `json:"at"`
}

// ListSweeps returns the tenant's recent sweep log (what WAS or WOULD BE deleted).
func (s *Service) ListSweeps(ctx context.Context, p auth.Principal, limit int) ([]SweepRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []SweepRow
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT store, cutoff, candidate_count, deleted_count, dry_run, at FROM retention_sweep_log WHERE tenant_id=$1 ORDER BY at DESC LIMIT $2`, p.TenantID, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r SweepRow
			if e := rows.Scan(&r.Store, &r.Cutoff, &r.CandidateCount, &r.DeletedCount, &r.DryRun, &r.At); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
