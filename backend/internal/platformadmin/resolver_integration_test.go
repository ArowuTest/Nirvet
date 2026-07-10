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

// Reinf-A: an immutable key resolves from CODE only — a planted DB row saying otherwise is inert.
func TestResolve_ImmutableIsInert(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	seedFlag(t, db, "global", "", "mfa.enforce", false) // attacker/mistake plants mfa.enforce=off globally
	if !NewFlagResolver(db).Enabled(context.Background(), tid, "mfa.enforce") {
		t.Fatal("immutable mfa.enforce must resolve ON from code, ignoring the planted DB row (Reinf-A)")
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

// open flag: global sets it, a tenant override wins.
func TestResolve_OpenPrecedence(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	r := NewFlagResolver(db)
	ctx := context.Background()
	seedFlag(t, db, "global", "", "ui.new_dashboard_beta", true)
	if !r.Enabled(ctx, tid, "ui.new_dashboard_beta") {
		t.Fatal("global-on open flag should be on")
	}
	seedFlag(t, db, "tenant", tid.String(), "ui.new_dashboard_beta", false)
	if r.Enabled(ctx, tid, "ui.new_dashboard_beta") {
		t.Fatal("tenant override should win for an open flag")
	}
}

// protected flag: a tenant may TIGHTEN toward secure but can NOT loosen below the platform baseline.
func TestResolve_ProtectedTightenOnly(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	r := NewFlagResolver(db)
	ctx := context.Background()

	// ai.egress_restricted secure=ON. A tenant row trying to turn it OFF (loosen) must be ignored.
	seedFlag(t, db, "tenant", tid.String(), "ai.egress_restricted", false)
	if !r.Enabled(ctx, tid, "ai.egress_restricted") {
		t.Fatal("a tenant must not loosen a protected flag (egress restriction stays ON)")
	}

	// soar.destructive_enabled secure=OFF. Platform enables it globally; a tenant may tighten it back OFF for itself.
	seedFlag(t, db, "global", "", "soar.destructive_enabled", true)
	if !r.Enabled(ctx, tid, "soar.destructive_enabled") {
		t.Fatal("platform-enabled destructive should be on at baseline")
	}
	seedFlag(t, db, "tenant", tid.String(), "soar.destructive_enabled", false)
	if r.Enabled(ctx, tid, "soar.destructive_enabled") {
		t.Fatal("a tenant tightening a protected flag toward secure must take effect (destructive OFF)")
	}
}

// ADMIN-004: the config-audit table is append-only — UPDATE and DELETE are rejected even by the app role.
func TestConfigAudit_AppendOnly(t *testing.T) {
	db := paDB(t)
	ctx := context.Background()
	var id uuid.UUID
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO platform_config_audit (entity, key, safety_class, reason)
			VALUES ('flag','ui.new_dashboard_beta','open','test') RETURNING id`).Scan(&id)
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
