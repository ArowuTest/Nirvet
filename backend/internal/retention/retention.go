// Package retention enforces per-tenant telemetry retention (§6.14 #188 HEAVY-3) — the ONLY feature that DELETES
// customer data. Every design choice fails SAFE toward keeping: legal-hold skips deletion outright; a missing/zero
// retention window keeps; a disabled policy only dry-runs (counts, never deletes); deletion runs in bounded
// batches and a batch error aborts that tenant's sweep (partial keep, never over-delete). It deletes ONLY raw
// telemetry — raw_events (and its blob_uri payload blob in the object store) + the normalized `events` projection —
// never alerts/incidents/evidence/audit. ClickHouse ages out via its own TTL (#160): one owner per store.
package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/metrics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// blobHash returns the sha256 hex of a blob URI for the deletion-attempt ledger (we record a hash, never
// the raw URI). Empty in → empty out (a raw event with no payload blob).
func blobHash(uri string) string {
	if uri == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(uri))
	return hex.EncodeToString(sum[:])
}

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
	// sweep (partial keep) — under-delete-never-over. Count eligible rows FIRST so the sweep-log ledger records a
	// real candidate-vs-deleted delta (a positive delta = rows a blob/DB failure left for the next sweep).
	var rawCand, evCand int64
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE received_at < $1`, cutoff).Scan(&rawCand)
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE collected_at < $1`, cutoff).Scan(&evCand)
		return nil
	})
	rawDeleted, err := s.deleteRawEvents(ctx, tenantID, cutoff)
	if err != nil {
		s.writeLog(ctx, tenantID, "raw_events", cutoff, rawCand, int64(rawDeleted), false) // record the partial delta
		return rawDeleted, err
	}
	evDeleted, err := s.deleteEvents(ctx, tenantID, cutoff)
	if err != nil {
		s.writeLog(ctx, tenantID, "raw_events", cutoff, rawCand, int64(rawDeleted), false)
		s.writeLog(ctx, tenantID, "events", cutoff, evCand, int64(evDeleted), false)
		return rawDeleted + evDeleted, err
	}
	s.writeLog(ctx, tenantID, "raw_events", cutoff, rawCand, int64(rawDeleted), false)
	s.writeLog(ctx, tenantID, "events", cutoff, evCand, int64(evDeleted), false)
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorEmail: "system:retention", Action: "retention.sweep",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"raw_deleted": rawDeleted, "events_deleted": evDeleted, "cutoff": cutoff.UTC()}})
	})
	return rawDeleted + evDeleted, nil
}

// deleteRawEvents deletes raw_events older than cutoff in bounded batches, deleting each row's payload blob
// FIRST and then its metadata row. This ordering is the COMPLIANCE-SAFE choice and is deliberately never
// database-first: a blob is never retained past its row, so the retention/privacy guarantee (destroy the
// payload) always holds. Object storage and Postgres cannot share one transaction, so two cross-store
// failures are possible; each is made OBSERVABLE in the retention_deletion_attempt ledger and each SELF-HEALS
// on a later sweep because blobstore.Store.Delete is contractually idempotent on a missing object:
//
//   - blob delete fails       → the row is kept (row+blob retained together); recorded blob_deleted=false and
//     retried on the next sweep. Fail-safe: nothing is deleted, no orphan.
//   - blob deleted, then the   → the row is TRANSIENTLY orphaned (payload gone, metadata row still present).
//     metadata-row delete fails   Recorded blob_deleted=true and counted in RetentionMetadataCleanupFailures.
//     The next sweep re-selects the row, the idempotent blob delete "succeeds"
//     (already gone), the row is finally removed, and the ledger entry is completed.
//
// A row that deletes cleanly in one pass is NOT written to the ledger (its aggregate is in retention_sweep_log);
// only anomalies are, so a persistently non-empty pending ledger means a genuine stuck deletion.
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
		var okHashes []string
		var failIDs []uuid.UUID
		var failHashes []string
		for _, c := range batch {
			if c.blob != "" {
				if e := s.blobs.Delete(ctx, c.blob); e != nil {
					failIDs = append(failIDs, c.id) // keep this row+blob together; ledger + retry next sweep
					failHashes = append(failHashes, blobHash(c.blob))
					continue
				}
			}
			ids = append(ids, c.id)
			okHashes = append(okHashes, blobHash(c.blob))
		}
		if len(failIDs) > 0 {
			s.recordAttempts(ctx, tenantID, failIDs, failHashes, false)
		}
		if len(ids) == 0 {
			return total, nil // nothing safely deletable this pass (only blob-delete failures remain)
		}
		var n int
		if err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			// Controlled evidence deletion via the fenced SECURITY DEFINER path (disables the immutability trigger
			// for this governed retention sweep only; refuses on legal_hold defense-in-depth).
			return tx.QueryRow(ctx, `SELECT retention_delete_raw($1, $2)`, tenantID, ids).Scan(&n)
		}); err != nil {
			// Blobs are already gone but the metadata rows remain → orphaned references. Record them so the
			// inconsistency is visible and reconcilable, count it, and abort this tenant's sweep (partial keep).
			// The next sweep re-selects these rows and completes the deletion (idempotent blob delete).
			s.recordAttempts(ctx, tenantID, ids, okHashes, true)
			metrics.RetentionMetadataCleanupFailures.Add(float64(len(ids)))
			return total, err
		}
		// Rows deleted: mark any previously-stuck ledger entries for these ids completed (no-op for clean rows).
		s.completeAttempts(ctx, tenantID, ids)
		total += n
		if len(batch) < batchSize {
			return total, nil
		}
	}
}

// recordAttempts upserts deletion-attempt ledger entries for rows that did NOT complete cleanly. blobDeleted
// distinguishes a blob-delete failure (false — row+blob both retained) from an orphaned reference (true — blob
// gone, metadata row remains). Best-effort: ledger bookkeeping must never block the retention sweep itself.
func (s *Service) recordAttempts(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID, hashes []string, blobDeleted bool) {
	if len(ids) == 0 {
		return
	}
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		for i, id := range ids {
			h := ""
			if i < len(hashes) {
				h = hashes[i]
			}
			_, _ = tx.Exec(ctx,
				`INSERT INTO retention_deletion_attempt (raw_event_id, blob_uri_hash, blob_deleted)
				 VALUES ($1, $2, $3)
				 ON CONFLICT (tenant_id, raw_event_id) DO UPDATE
				    SET blob_deleted    = retention_deletion_attempt.blob_deleted OR EXCLUDED.blob_deleted,
				        retry_count     = retention_deletion_attempt.retry_count + 1,
				        last_attempt_at = now()`,
				id, h, blobDeleted)
		}
		return nil
	})
}

// completeAttempts marks any ledger entries for the given (now-deleted) rows as completed. It is a no-op for
// rows that deleted cleanly on the first pass (no ledger entry) — the common case.
func (s *Service) completeAttempts(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) {
	if len(ids) == 0 {
		return
	}
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, _ = tx.Exec(ctx,
			`UPDATE retention_deletion_attempt
			    SET blob_deleted = true, row_deleted = true, completed_at = now(), last_attempt_at = now()
			  WHERE raw_event_id = ANY($1) AND completed_at IS NULL`, ids)
		return nil
	})
}

// reconcileMetrics publishes the pending/oldest gauges from the cross-tenant ledger summary (SECURITY DEFINER,
// so it aggregates every tenant), and prunes long-completed ledger rows so the table stays bounded. Called
// once per sweep cycle by SweepAll.
func (s *Service) reconcileMetrics(ctx context.Context) {
	_ = s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var missing int64
		var oldest *time.Time
		if e := tx.QueryRow(ctx, `SELECT rows_with_missing_blob, oldest_pending FROM retention_pending_summary()`).Scan(&missing, &oldest); e != nil {
			return nil // best-effort observability; never fail the sweep
		}
		metrics.RetentionRowsWithMissingBlob.Set(float64(missing))
		if oldest != nil {
			metrics.RetentionOldestPendingCleanupSeconds.Set(time.Since(*oldest).Seconds())
		} else {
			metrics.RetentionOldestPendingCleanupSeconds.Set(0)
		}
		// Keep a week of completion evidence, then prune so the ledger stays bounded.
		_, _ = tx.Exec(ctx, `SELECT retention_prune_completed_attempts('7 days')`)
		return nil
	})
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
	// After the cycle, publish the reconciliation gauges (rows still orphaned, oldest pending) and prune
	// long-completed ledger entries — the operator's evidence that the transient inconsistency is healing.
	s.reconcileMetrics(ctx)
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
