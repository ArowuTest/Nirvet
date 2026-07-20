package retention

// §6.14 B3 jurisdictional-retention tests (gate §3). The two load-bearing invariants — floor-wins-on-contradiction and
// ceiling-dormant-until-armed — are PURE (DB-free) so they run everywhere. The rest are DB-gated on the retDB harness.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArowuTest/nirvet/internal/platform/database"
)

func ip(n int) *int { return &n }

// #1 LOAD-BEARING (gate §3.1): floor 90 + ceiling 30 → effective 90 (the FLOOR wins), never 30. A 60-day-old row is
// therefore RETAINED (60 < 90). Mutation: swap the nesting to min(max(inner,floor),ceiling) → full becomes 30 → RED.
func TestClampWindow_FloorWinsOnContradiction(t *testing.T) {
	base, full := clampWindow(365 /*inner*/, 90 /*floor*/, 30 /*ceiling*/)
	if full != 90 {
		t.Fatalf("floor must win on contradiction: full=%d, want 90 (NOT the ceiling 30)", full)
	}
	if base != 365 {
		t.Fatalf("base = max(floor, inner) = 365, got %d", base)
	}
	// A 60-day retention would keep data younger than the window; with effective 90, 60-day data is retained.
	if 60 >= full {
		t.Fatalf("with the floor winning (90d), 60-day-old data must be inside the window (retained)")
	}
}

// clampWindow edge cases: no jurisdiction is a no-op; a floor only lengthens; a ceiling only shortens; a ceiling above
// the inner window does not bind.
func TestClampWindow_Cases(t *testing.T) {
	if b, f := clampWindow(200, 0, 0); b != 200 || f != 200 {
		t.Fatalf("no jurisdiction → base=full=inner; got %d/%d", b, f)
	}
	if b, f := clampWindow(30, 90, 0); b != 90 || f != 90 {
		t.Fatalf("floor only lengthens → 90/90; got %d/%d", b, f)
	}
	if b, f := clampWindow(365, 0, 30); b != 365 || f != 30 {
		t.Fatalf("ceiling only shortens the full window → base 365, full 30; got %d/%d", b, f)
	}
	if b, f := clampWindow(30, 0, 90); b != 30 || f != 30 {
		t.Fatalf("a ceiling ABOVE the inner window does not bind → 30/30; got %d/%d", b, f)
	}
}

// #6 (gate §3.6, pure half): the ceiling is DORMANT until armed — with armed=false the delete uses the base window
// (ceiling ignored); flipping armed=true makes the same case use the (shorter) full window. Proves the arm is
// load-bearing, not decorative. reportDays always shows the ceiling-applied window.
func TestDeleteDays_CeilingDormantUntilArmed(t *testing.T) {
	wr := windowResolution{baseDays: 365, fullDays: 90, ceilingDays: 90, ok: true}
	if !wr.ceilingBinds() {
		t.Fatal("ceiling (90) below base (365) must bind")
	}
	wr.armed = false
	if wr.deleteDays() != 365 {
		t.Fatalf("disarmed: delete uses the base window (ceiling dormant); got %d want 365", wr.deleteDays())
	}
	if wr.reportDays() != 90 {
		t.Fatalf("report always shows the ceiling-applied window; got %d want 90", wr.reportDays())
	}
	wr.armed = true
	if wr.deleteDays() != 90 {
		t.Fatalf("armed: the ceiling binds → delete uses the full window; got %d want 90", wr.deleteDays())
	}
}

// ===================== DB-gated (retDB harness) =====================

func setCountry(t *testing.T, db *database.DB, tid uuid.UUID, country string) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET country=$2 WHERE id=$1`, tid, country)
		return e
	}); err != nil {
		t.Fatalf("set country: %v", err)
	}
}

func setJurisdiction(t *testing.T, db *database.DB, key string, minD, maxD *int) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO jurisdiction_retention (jurisdiction_key, name, min_retain_days, max_retain_days)
			 VALUES ($1,$1,$2,$3) ON CONFLICT (jurisdiction_key) DO UPDATE SET min_retain_days=EXCLUDED.min_retain_days, max_retain_days=EXCLUDED.max_retain_days`,
			key, minD, maxD)
		return e
	}); err != nil {
		t.Fatalf("set jurisdiction: %v", err)
	}
}

func setArmed(t *testing.T, db *database.DB, armed bool) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE jurisdiction_delete_armed SET armed=$1 WHERE id=1`, armed)
		return e
	}); err != nil {
		t.Fatalf("set armed: %v", err)
	}
	t.Cleanup(func() { // never leave the shared singleton armed for other packages/tests
		_ = db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE jurisdiction_delete_armed SET armed=false WHERE id=1`)
			return e
		})
	})
}

func jLedger(t *testing.T, db *database.DB, tid uuid.UUID) (count int, key string, ceilingBinds, armed bool, deleted int64) {
	t.Helper()
	_ = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM retention_jurisdiction_ledger WHERE tenant_id=$1`, tid).Scan(&count)
		// A sweep writes one ledger row per store (raw_events, events); pick the one carrying the actual delete
		// (raw_events had the row; events had none) by ordering on deleted_count so attribution reflects the delete.
		_ = tx.QueryRow(ctx,
			`SELECT jurisdiction_key, ceiling_binds, armed, deleted_count FROM retention_jurisdiction_ledger
			  WHERE tenant_id=$1 ORDER BY deleted_count DESC, at DESC LIMIT 1`, tid).Scan(&key, &ceilingBinds, &armed, &deleted)
		return nil
	})
	return
}

// #6 (DB half): armed is load-bearing end-to-end. inner=365, ceiling 30. Disarmed → a 60-day row is KEPT (deletes at
// base 365). Arm → the same row is DELETED (deletes at full 30).
func TestRetention_CeilingDormantThenArmedDeletes(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 365)
	ctx := context.Background()
	setCountry(t, db, tid, "GH")
	setJurisdiction(t, db, "GH", nil, ip(30))
	_, _ = svc.SetPolicy(ctx, p, true, nil)
	old, _ := seedRaw(t, db, blobs, tid, oldT, false) // ~60 days old

	setArmed(t, db, false)
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep disarmed: %v", err)
	}
	if !rawExists(t, db, tid, old) {
		t.Fatal("ceiling DORMANT (disarmed): the 60-day row must be kept (delete window = base 365)")
	}

	setArmed(t, db, true)
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep armed: %v", err)
	}
	if rawExists(t, db, tid, old) {
		t.Fatal("ceiling ARMED: the 60-day row must be deleted (delete window = full 30)")
	}
}

// #2 (gate §3.2): legal hold is supreme — a held tenant with an armed aggressive ceiling deletes NOTHING.
func TestRetention_LegalHoldSupremeOverCeiling(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 365)
	ctx := context.Background()
	setCountry(t, db, tid, "GH")
	setJurisdiction(t, db, "GH", nil, ip(30))
	setArmed(t, db, true)
	_, _ = svc.SetPolicy(ctx, p, true, nil)
	old, _ := seedRaw(t, db, blobs, tid, oldT, false)
	_ = db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET legal_hold=true WHERE id=$1`, tid)
		return e
	})
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !rawExists(t, db, tid, old) {
		t.Fatal("legal hold must beat an armed ceiling — the row was deleted")
	}
}

// #3 (gate §3.3): the SD delete function re-checks legal_hold INSIDE the delete tx (not just a stale pre-flight) — a
// direct call on a held tenant refuses.
func TestRetention_SDDeleteRefusesHoldInTx(t *testing.T) {
	db := retDB(t)
	_, blobs := retSvc(t, db)
	_, tid := retTenant(t, db, 365)
	ctx := context.Background()
	id, _ := seedRaw(t, db, blobs, tid, oldT, false)
	_ = db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET legal_hold=true WHERE id=$1`, tid)
		return e
	})
	err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT retention_delete_raw($1,$2)`, tid, []uuid.UUID{id}).Scan(&n)
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "legal hold") {
		t.Fatalf("the SD delete must refuse inside the tx on legal hold; got err=%v", err)
	}
}

// #4 (gate §3.4): a tenant's ceiling deletes ONLY its own telemetry — a second tenant's data at the same age is
// untouched.
func TestRetention_CeilingTenantScoped(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	ctx := context.Background()
	pa, tidA := retTenant(t, db, 365)
	_, tidB := retTenant(t, db, 365)
	setCountry(t, db, tidA, "GH")
	setCountry(t, db, tidB, "GH")
	setJurisdiction(t, db, "GH", nil, ip(30))
	setArmed(t, db, true)
	_, _ = svc.SetPolicy(ctx, pa, true, nil)
	// tenant B's policy stays default (disabled) → B never deletes regardless; and we only sweep A.
	oldA, _ := seedRaw(t, db, blobs, tidA, oldT, false)
	oldB, _ := seedRaw(t, db, blobs, tidB, oldT, false)
	if _, err := svc.SweepTenant(ctx, tidA); err != nil {
		t.Fatalf("sweep A: %v", err)
	}
	if rawExists(t, db, tidA, oldA) {
		t.Fatal("tenant A's old row must be deleted under its armed ceiling")
	}
	if !rawExists(t, db, tidB, oldB) {
		t.Fatal("tenant B's row must be untouched — the sweep is tenant-scoped")
	}
}

// #5 (gate §3.5): dry-run is fail-safe — an armed ceiling with the tenant policy DISABLED deletes nothing (only
// reports), and records a dry-run jurisdiction-ledger row.
func TestRetention_CeilingDryRunFailSafe(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 365)
	ctx := context.Background()
	setCountry(t, db, tid, "GH")
	setJurisdiction(t, db, "GH", nil, ip(30))
	setArmed(t, db, true)
	// policy stays DISABLED (dry-run) — do NOT SetPolicy(enabled=true)
	old, _ := seedRaw(t, db, blobs, tid, oldT, false)
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !rawExists(t, db, tid, old) {
		t.Fatal("a disabled policy must NOT delete even with an armed ceiling (dry-run)")
	}
	_ = p
	cnt, _, _, _, _ := jLedger(t, db, tid)
	if cnt == 0 {
		t.Fatal("a jurisdiction sweep (even dry-run) must record a ledger row for attribution")
	}
}

// #8 (gate §3.8): a jurisdictional delete is attributable — it writes a retention_jurisdiction_ledger row naming the
// jurisdiction, with ceiling_binds + armed + deleted_count.
func TestRetention_JurisdictionLedgerAttribution(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 365)
	ctx := context.Background()
	setCountry(t, db, tid, "GH")
	setJurisdiction(t, db, "GH", nil, ip(30))
	setArmed(t, db, true)
	_, _ = svc.SetPolicy(ctx, p, true, nil)
	_, _ = seedRaw(t, db, blobs, tid, oldT, false)
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	cnt, key, binds, armed, deleted := jLedger(t, db, tid)
	if cnt == 0 || key != "GH" || !binds || !armed || deleted < 1 {
		t.Fatalf("expected an attributed ledger row (key=GH, ceiling_binds, armed, deleted>=1); got cnt=%d key=%q binds=%v armed=%v deleted=%d",
			cnt, key, binds, armed, deleted)
	}
}
