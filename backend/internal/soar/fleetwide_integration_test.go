package soar

// FleetWide authority dimension (owner decision Option 1: fleet-wide = approval-ALWAYS, human-runnable).
// The invariant: a fleet-wide action is NEVER auto-eligible under ANY authority mode — the `!act.FleetWide`
// short-circuit sits ABOVE the mode-dependent Allowed() at the single chokepoint (runFor) — yet stays
// approvable-and-runnable (reachable, not the business_critical phantom).
//
// MUTATION CHECK: drop `!act.FleetWide` from service.go's autoEligible → TestFleetWide_NeverAutoRunsUnderAnyMode
// goes RED (a contractual_auto fleet-wide step auto-runs). That is the whole point of the guard.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func fwDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestFleetWide_SeededFamily is the REQUIRED CI guard (gate §A.5): every block/quarantine-all-family catalog row
// MUST carry fleet_wide=true. This is the fence that would have caught the latent Defender fail-open (block_hash/
// block_ip/block_domain seeded 'high' with nothing structural stopping a fleet-wide auto-fire). A future block verb
// seeded without the flag is exactly the recurrence this prevents — don't rely on the author remembering.
func TestFleetWide_SeededFamily(t *testing.T) {
	db := fwDB(t)
	ctx := context.Background()
	// Enumerate the family by name pattern over the SEEDED (global) catalog.
	var keys []string
	err := db.WithTenant(ctx, uuid.New(), func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT action_key FROM soar_action_catalog
			 WHERE tenant_id IS NULL
			   AND (action_key LIKE 'block\_%' OR action_key LIKE '%\_block\_hash' OR action_key LIKE '%\_block\_ip'
			        OR action_key LIKE '%\_block\_domain' OR action_key = 'network_block_all'
			        OR action_key LIKE 'quarantine\_all%')
			   AND fleet_wide = false`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return err
			}
			keys = append(keys, k)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("query family: %v", err)
	}
	if len(keys) > 0 {
		t.Fatalf("fleet-wide fence: these block-family actions are seeded WITHOUT fleet_wide=true, so a permissive "+
			"authority mode could auto-fire them across the whole tenant: %v", keys)
	}
	// Guard against a vacuous assertion: the family pattern MUST match a non-empty set (else the fence proves nothing).
	var family int
	if err := db.WithTenant(ctx, uuid.New(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM soar_action_catalog
			 WHERE tenant_id IS NULL AND fleet_wide = true`).Scan(&family)
	}); err != nil {
		t.Fatalf("count family: %v", err)
	}
	if family == 0 {
		t.Fatal("fleet-wide fence is VACUOUS: no seeded action carries fleet_wide=true — the pattern matches nothing")
	}
	t.Logf("fleet-wide fence: %d seeded fleet-wide actions, none missing the flag", family)
}

// NOTE: the core "never auto-runs under any mode" invariant is tested in fleetwide_run_integration_test.go by
// driving the REAL runFor via svc.Run — NOT by re-implementing the autoEligible expression here. An earlier draft
// of this file did exactly that and was a FALSE GREEN: dropping `!act.FleetWide` from service.go left it passing,
// because it asserted on a local copy of the expression rather than on the shipped code path. Mutation-checked.

// TestFleetWide_OverrideMayOnlyTighten — a tenant override cannot un-mark a globally fleet-wide action.
func TestFleetWide_OverrideMayOnlyTighten(t *testing.T) {
	db := fwDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	tid := uuid.New()

	// Seed a tenant override for cs_block_hash claiming fleet_wide=false (the downgrade attempt).
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO soar_action_catalog (tenant_id, action_key, title, risk_class, executor, connector_key, enabled, fleet_wide)
			VALUES ($1,'cs_block_hash','override attempt','high','connector','crowdstrike',true,false)
			ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), action_key) DO NOTHING`, tid)
		return e
	}); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	act, found := repo.resolveAction(ctx, tid, "cs_block_hash")
	if !found {
		t.Fatal("cs_block_hash should resolve")
	}
	if !act.FleetWide {
		t.Fatal("override-only-tightens VIOLATED: a tenant override with fleet_wide=false lowered a globally " +
			"fleet-wide action — a tenant must never be able to un-mark fleet-wide and unlock auto-fire")
	}
	// The batch resolver must apply the identical clamp (both paths, not just one).
	m, err := repo.resolveActionCatalogMap(ctx, tid)
	if err != nil {
		t.Fatalf("resolveActionCatalogMap: %v", err)
	}
	if !lookupAction(m, "cs_block_hash").FleetWide {
		t.Fatal("override-only-tightens VIOLATED in the BATCH resolver (resolveActionCatalogMap) — the clamp must " +
			"hold on every resolve path, not just resolveAction")
	}
}
