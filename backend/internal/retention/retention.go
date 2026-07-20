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
	Enabled         bool   `json:"enabled"`
	WindowDays      *int   `json:"window_days,omitempty"` // nil = use the entitlement window
	EffectiveDays   int    `json:"effective_days"`        // window the ACTUAL delete uses (armed? full : base); 0 = keep
	EntitlementDays int    `json:"entitlement_days"`
	Jurisdiction    string `json:"jurisdiction,omitempty"`
	FloorDays       int    `json:"floor_days,omitempty"`   // jurisdiction retain-at-least (0 = none)
	CeilingDays     int    `json:"ceiling_days,omitempty"` // jurisdiction delete-after (0 = none)
	CeilingArmed    bool   `json:"ceiling_armed"`          // is jurisdictional-ceiling deletion armed (go-live D-arm-retention)
}

// windowResolution is the SINGLE window computation for a tenant — the ONLY producer of the window that feeds the
// delete path (check-retention-window-single-path.sh enforces there is no second producer). Semantics: DAYS of
// retention (larger = keep longer = delete less). B3 gate 2a.
type windowResolution struct {
	enabled      bool
	ok           bool // a usable window exists (entitlement + tenant window > 0)
	jurisdiction string
	entDays      int
	inner        int // min(tenant override, entitlement) — the pre-jurisdiction tighten-only window
	floorDays    int // jurisdiction floor (retain >=; 0 = none)
	ceilingDays  int // jurisdiction ceiling (delete after; 0 = none)
	baseDays     int // max(floor, inner) — window when the ceiling is DORMANT (disarmed)
	fullDays     int // max(floor, min(inner, ceiling)) — window with the ceiling applied
	armed        bool
}

// ceilingBinds reports whether the ceiling actually shortened the window below the (floor-lengthened) base.
func (wr windowResolution) ceilingBinds() bool { return wr.fullDays < wr.baseDays }

// deleteDays is the window used for the ACTUAL delete: the ceiling only shortens it when jurisdictional deletion is
// ARMED (go-live). Disarmed, the ceiling is dormant and deletion uses the floor-lengthened base window — so floor and
// tighten-only-tenant deletions proceed as before, but the destructive ceiling waits for the arm.
func (wr windowResolution) deleteDays() int {
	if wr.armed {
		return wr.fullDays
	}
	return wr.baseDays
}

// reportDays is the window used for the dry-run/report — ALWAYS the ceiling-applied window, so an operator SEES what
// the ceiling would delete even while it is dormant.
func (wr windowResolution) reportDays() int { return wr.fullDays }

// clampWindow is the PURE clamp (gate 2a): base = max(floor, inner); full = max(floor, min(inner, ceiling)). The floor
// is the OUTER max, so a contradictory floor>ceiling resolves to the FLOOR (retain longer), NEVER the ceiling — when
// rules conflict, resolve toward RETENTION. This is the load-bearing property; the floor-wins test mutates the nesting
// (to min(max(inner,floor),ceiling)) and goes RED.
func clampWindow(inner, floor, ceiling int) (base, full int) {
	base = maxInt(floor, inner)
	ic := inner
	if ceiling > 0 && ceiling < ic {
		ic = ceiling
	}
	full = maxInt(floor, ic)
	return
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// cutoffFor turns a retention window (days) into the delete cutoff. Centralised so the cutoff-from-window computation
// has ONE home (the single-path fence asserts no other place derives a delete cutoff from a raw duration).
func cutoffFor(days int) time.Time { return time.Now().Add(-time.Duration(days) * 24 * time.Hour) }

// jurisdictionFor reads the tenant's country → its jurisdiction_retention floor/ceiling. Unknown jurisdiction (no
// country set, or no matching config row) → (key, 0, 0): NO clamp, fail toward RETENTION — never invent a delete
// window from an unrecognised regime (gate 2b).
func (s *Service) jurisdictionFor(ctx context.Context, tenantID uuid.UUID) (key string, floor, ceiling int) {
	_ = s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var country string
		if e := tx.QueryRow(ctx, `SELECT COALESCE(country,'') FROM tenants WHERE id=$1`, tenantID).Scan(&country); e != nil || country == "" {
			return nil
		}
		key = country
		var minD, maxD *int
		if e := tx.QueryRow(ctx,
			`SELECT min_retain_days, max_retain_days FROM jurisdiction_retention WHERE jurisdiction_key=$1`, country).Scan(&minD, &maxD); e != nil {
			return nil // unknown jurisdiction → no clamp
		}
		if minD != nil && *minD > 0 {
			floor = *minD
		}
		if maxD != nil && *maxD > 0 {
			ceiling = *maxD
		}
		return nil
	})
	return key, floor, ceiling
}

// armedNow reads the operator's jurisdiction_delete_armed flag (seeded false). Fail-safe: any read error → false (the
// ceiling's destructive enforcement stays dormant).
func (s *Service) armedNow(ctx context.Context) bool {
	armed := false
	_ = s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT armed FROM jurisdiction_delete_armed WHERE id=1`).Scan(&armed)
		return nil
	})
	return armed
}

// resolveWindow is the SOLE producer of the retention window. It reads the tenant policy + entitlement (tighten-only
// inner window), then applies the jurisdiction floor/ceiling via clampWindow, and reads the arm flag. ok=false → no
// usable window → the caller KEEPS everything (fail-safe). No other function computes a window that feeds a delete.
func (s *Service) resolveWindow(ctx context.Context, tenantID uuid.UUID) windowResolution {
	var wr windowResolution
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var override *int
		_ = tx.QueryRow(ctx,
			`SELECT enabled, window_days FROM retention_policy WHERE tenant_id=$1 OR tenant_id IS NULL
			  ORDER BY tenant_id NULLS LAST LIMIT 1`, tenantID).Scan(&wr.enabled, &override)
		if e := tx.QueryRow(ctx, `SELECT retention_days FROM entitlements WHERE tenant_id=$1`, tenantID).Scan(&wr.entDays); e != nil {
			wr.entDays = 0
		}
		wr.inner = wr.entDays
		if override != nil && *override > 0 && *override < wr.inner {
			wr.inner = *override // tighten-only: a tenant may keep for LESS, never more than its entitlement
		}
		return nil
	})
	if wr.entDays <= 0 || wr.inner <= 0 {
		wr.ok = false
		return wr // fail-safe: no usable window → KEEP (a floor with nothing to delete is trivially satisfied)
	}
	wr.ok = true
	wr.jurisdiction, wr.floorDays, wr.ceilingDays = s.jurisdictionFor(ctx, tenantID)
	wr.baseDays, wr.fullDays = clampWindow(wr.inner, wr.floorDays, wr.ceilingDays)
	wr.armed = s.armedNow(ctx)
	return wr
}

// writeJurisdictionLedger records, for attribution, every sweep where a jurisdiction rule participated (dry-runs too):
// the rule + the windows it produced + whether the ceiling bound + whether it was armed. Append-only (mig 0138). So a
// jurisdictional delete — irreversible — is always attributable to the regime that drove it.
func (s *Service) writeJurisdictionLedger(ctx context.Context, tenantID uuid.UUID, wr windowResolution, store string, deleted int64, dryRun bool) {
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO retention_jurisdiction_ledger
			   (tenant_id, jurisdiction_key, floor_days, ceiling_days, base_days, effective_days, ceiling_binds, armed, store, deleted_count, dry_run)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			tenantID, wr.jurisdiction, wr.floorDays, wr.ceilingDays, wr.baseDays, wr.deleteDays(), wr.ceilingBinds(), wr.armed, store, deleted, dryRun)
		return e
	})
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
		return 0, nil // legal hold / unreadable → preserve, never delete (short-circuit BEFORE any window compute)
	}
	wr := s.resolveWindow(ctx, tenantID)
	if !wr.ok {
		return 0, nil // no usable window → keep
	}
	hasJurisdiction := wr.floorDays > 0 || wr.ceilingDays > 0
	// The DELETE uses deleteDays (the ceiling only shortens when armed); the dry-run REPORT uses reportDays (always the
	// ceiling-applied window, so the ceiling's dormant would-delete is visible).
	deleteCutoff := cutoffFor(wr.deleteDays())
	reportCutoff := cutoffFor(wr.reportDays())

	if !wr.enabled {
		// Dry-run: count what WOULD be deleted (at the ceiling-applied report window), log it, delete NOTHING.
		var rawN, evN int64
		_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE received_at < $1`, reportCutoff).Scan(&rawN)
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE collected_at < $1`, reportCutoff).Scan(&evN)
			return nil
		})
		s.writeLog(ctx, tenantID, "raw_events", reportCutoff, rawN, 0, true)
		s.writeLog(ctx, tenantID, "events", reportCutoff, evN, 0, true)
		if hasJurisdiction {
			s.writeJurisdictionLedger(ctx, tenantID, wr, "raw_events", 0, true)
			s.writeJurisdictionLedger(ctx, tenantID, wr, "events", 0, true)
		}
		return 0, nil
	}

	// Enabled: delete raw_events (+ their payload blobs) then events, in bounded batches, at the DELETE window. A batch
	// error aborts the sweep (partial keep) — under-delete-never-over. Count eligible rows FIRST so the sweep-log
	// records a real candidate-vs-deleted delta (a positive delta = rows a blob/DB failure left for the next sweep).
	var rawCand, evCand int64
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE received_at < $1`, deleteCutoff).Scan(&rawCand)
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE collected_at < $1`, deleteCutoff).Scan(&evCand)
		return nil
	})
	rawDeleted, err := s.deleteRawEvents(ctx, tenantID, deleteCutoff)
	if err != nil {
		s.writeLog(ctx, tenantID, "raw_events", deleteCutoff, rawCand, int64(rawDeleted), false) // record the partial delta
		return rawDeleted, err
	}
	evDeleted, err := s.deleteEvents(ctx, tenantID, deleteCutoff)
	if err != nil {
		s.writeLog(ctx, tenantID, "raw_events", deleteCutoff, rawCand, int64(rawDeleted), false)
		s.writeLog(ctx, tenantID, "events", deleteCutoff, evCand, int64(evDeleted), false)
		return rawDeleted + evDeleted, err
	}
	s.writeLog(ctx, tenantID, "raw_events", deleteCutoff, rawCand, int64(rawDeleted), false)
	s.writeLog(ctx, tenantID, "events", deleteCutoff, evCand, int64(evDeleted), false)
	if hasJurisdiction {
		s.writeJurisdictionLedger(ctx, tenantID, wr, "raw_events", int64(rawDeleted), false)
		s.writeJurisdictionLedger(ctx, tenantID, wr, "events", int64(evDeleted), false)
	}
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{ActorEmail: "system:retention", Action: "retention.sweep",
			Target: "tenant:" + tenantID.String(), Metadata: map[string]any{"raw_deleted": rawDeleted, "events_deleted": evDeleted,
				"cutoff": deleteCutoff.UTC(), "jurisdiction": wr.jurisdiction, "armed": wr.armed, "ceiling_binds": wr.ceilingBinds()}})
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

// GetPolicy returns the tenant's effective retention view — including the jurisdiction floor/ceiling and whether the
// ceiling's destructive enforcement is armed (so a tenant admin sees the sovereign window that governs their data).
func (s *Service) GetPolicy(ctx context.Context, p auth.Principal) Policy {
	wr := s.resolveWindow(ctx, p.TenantID)
	eff := 0
	if wr.ok {
		eff = wr.deleteDays()
	}
	var override *int
	_ = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT window_days FROM retention_policy WHERE tenant_id=$1`, p.TenantID).Scan(&override)
	})
	return Policy{Enabled: wr.enabled, WindowDays: override, EffectiveDays: eff, EntitlementDays: wr.entDays,
		Jurisdiction: wr.jurisdiction, FloorDays: wr.floorDays, CeilingDays: wr.ceilingDays, CeilingArmed: wr.armed}
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
