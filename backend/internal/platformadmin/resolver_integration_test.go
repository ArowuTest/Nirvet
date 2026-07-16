package platformadmin

// §6.18 #122 P-1 — resolver + config-audit integration tests (migrated DB): immutable-inert (Reinf-A), fail-safe
// unknown, open precedence, protected tighten-only, and append-only config audit.

import (
	"context"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func paDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func paTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "pa-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

// seedFlag writes a flag row. Flags are platform-managed → system context (RLS write policy = app_current_tenant() IS NULL).
func seedFlag(t *testing.T, db *database.DB, scope, ref, key string, enabled bool) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO platform_feature_flags (key, scope, scope_ref, enabled) VALUES ($1,$2,$3,$4)
			ON CONFLICT (key, scope, scope_ref) DO UPDATE SET enabled=EXCLUDED.enabled`, key, scope, ref, enabled)
		return e
	}); err != nil {
		t.Fatalf("seed flag: %v", err)
	}
}

// clearFlag removes every row for a key — for a test that must start from a clean baseline for that key on the
// shared, persistent test DB (seedFlag rows persist across runs).
func clearFlag(t *testing.T, db *database.DB, key string) {
	t.Helper()
	if err := db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM platform_feature_flags WHERE key=$1`, key)
		return e
	}); err != nil {
		t.Fatalf("clear flag: %v", err)
	}
}

// Reinf-A: an immutable key resolves from CODE only — a planted DB row saying otherwise is inert.
func TestResolve_ImmutableIsInert(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedFlag(t, db, "global", "", TestFlagImmutable, false) // attacker/mistake plants the immutable flag OFF globally
	if !NewFlagResolver(db).Enabled(context.Background(), tid, TestFlagImmutable) {
		t.Fatal("an immutable flag must resolve ON from code, ignoring the planted DB row (Reinf-A)")
	}
}

// Fail-safe: an unknown flag resolves to its secure default (false), never a permissive fallback.
func TestResolve_UnknownFailSafe(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	if NewFlagResolver(db).Enabled(context.Background(), tid, "totally.unregistered.flag") {
		t.Fatal("unknown flag must resolve OFF (fail-safe)")
	}
}

// P-5 adversarial: a tenant-scoped flag override for tenant A must NOT be visible to tenant B — B resolves the
// global/secure baseline, never A's row. Cross-tenant flag isolation under RLS + scope_ref filtering.
func TestResolve_CrossTenantFlagIsolation(t *testing.T) {
	db := paDB(t)
	a := paTenant(t, db)
	b := paTenant(t, db)
	r := NewFlagResolver(db)
	ctx := context.Background()

	// Clean baseline for the key (shared persistent DB): no global row, so B's only possible source is its own
	// tenant row — which it does not have.
	clearFlag(t, db, TestFlagOpen)
	// Tenant A turns an open flag ON for itself only (secure default is OFF).
	seedFlag(t, db, "tenant", a.String(), TestFlagOpen, true)
	if !r.Enabled(ctx, a, TestFlagOpen) {
		t.Fatal("tenant A must see its own override (on)")
	}
	if r.Enabled(ctx, b, TestFlagOpen) {
		t.Fatal("cross-tenant leak: tenant B must NOT see tenant A's flag override (resolves to secure default off)")
	}
}

// open flag: global sets it, a tenant override wins.
func TestResolve_OpenPrecedence(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	r := NewFlagResolver(db)
	ctx := context.Background()
	seedFlag(t, db, "global", "", TestFlagOpen, true)
	if !r.Enabled(ctx, tid, TestFlagOpen) {
		t.Fatal("global-on open flag should be on")
	}
	seedFlag(t, db, "tenant", tid.String(), TestFlagOpen, false)
	if r.Enabled(ctx, tid, TestFlagOpen) {
		t.Fatal("tenant override should win for an open flag")
	}
}

// protected flag: a tenant may TIGHTEN toward secure but can NOT loosen below the platform baseline.
func TestResolve_ProtectedTightenOnly(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	r := NewFlagResolver(db)
	ctx := context.Background()

	// Start from a known baseline. platform_feature_flags is global state shared by every test in this package, so
	// another test that leaves a GLOBAL row behind would silently move this test's baseline and make it assert
	// something it did not intend. (This bit: the four-eyes tests in service_integration_test.go set a global row
	// for the same protected fixture, and without this clear, base came from THEIR row rather than the secure
	// default.)
	clearFlag(t, db, TestFlagProtected)
	clearFlag(t, db, TestFlagProtectedOff)

	// The protected fixture is secure=ON. A tenant row trying to turn it OFF (loosen) must be ignored.
	seedFlag(t, db, "tenant", tid.String(), TestFlagProtected, false)
	if !r.Enabled(ctx, tid, TestFlagProtected) {
		t.Fatal("a tenant must not loosen a protected flag (it stays at the secure baseline, ON)")
	}

	// The other shape: a protected flag whose secure default is OFF. The platform enables it globally; a tenant may
	// tighten it back OFF for itself.
	seedFlag(t, db, "global", "", TestFlagProtectedOff, true)
	if !r.Enabled(ctx, tid, TestFlagProtectedOff) {
		t.Fatal("a platform-enabled protected flag should be on at baseline")
	}
	seedFlag(t, db, "tenant", tid.String(), TestFlagProtectedOff, false)
	if r.Enabled(ctx, tid, TestFlagProtectedOff) {
		t.Fatal("a tenant tightening a protected flag toward secure must take effect (back to OFF)")
	}
}

// ADMIN-004: the config-audit table is append-only — UPDATE and DELETE are rejected even by the app role.
func TestConfigAudit_AppendOnly(t *testing.T) {
	db := paDB(t)
	ctx := context.Background()
	var id uuid.UUID
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO platform_config_audit (entity, key, safety_class, reason)
			VALUES ('flag',$1,'open','test') RETURNING id`, TestFlagOpen).Scan(&id)
	}); err != nil {
		t.Fatalf("insert audit: %v", err)
	}
	// Two layers block mutation: the app role has UPDATE/DELETE revoked (permission denied, caught first), and the
	// trigger is the backstop for the owner (append-only). As nirvet_app we hit the REVOKE; accept either signal.
	blocked := func(e error) bool {
		return e != nil && (strings.Contains(e.Error(), "append-only") || strings.Contains(e.Error(), "permission denied"))
	}
	upErr := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE platform_config_audit SET reason='tampered' WHERE id=$1`, id)
		return e
	})
	if !blocked(upErr) {
		t.Fatalf("UPDATE on config audit must be rejected (append-only / permission denied), got %v", upErr)
	}
	delErr := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM platform_config_audit WHERE id=$1`, id)
		return e
	})
	if !blocked(delErr) {
		t.Fatalf("DELETE on config audit must be rejected (append-only / permission denied), got %v", delErr)
	}
}
