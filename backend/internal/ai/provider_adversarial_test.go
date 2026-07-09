package ai

// §6.12 #117 A-6 — the dedicated adversarial round. Most of the gate's Verify list is proven by the A-3/A-4/A-5
// suites (allowlist-internal-works, non-allowlisted-refused, path-smuggle, redirect-refused, kind-restricted
// fail-closed, cross-tenant read isolation, tighten-only 403, cleartext warning, key unseal + fail-closed). The
// probes here close the one path opened by migration 0068 (widening the ai_provider write policy to permit the
// global row under system context): a TENANT must still be unable to forge/write the global row or another
// tenant's row. If 0068 were too loose, these would let a tenant hijack the platform default provider for everyone.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A tenant context (app_current_tenant() = its id, never NULL) must NOT be able to insert the GLOBAL row
// (tenant_id NULL) — the 0068 disjunct `tenant_id IS NULL AND app_current_tenant() IS NULL` can only be true under
// system context. This is the probe that proves 0068 did not open a platform-default-hijack hole.
func TestAdversarial_TenantCannotForgeGlobalRow(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ai_provider (tenant_id, provider_kind, model) VALUES (NULL, 'disabled', '')`)
		return e
	})
	if err == nil {
		t.Fatal("a tenant must NOT be able to write the global (tenant_id NULL) provider row — 0068 hole")
	}
}

// A tenant must not write ANOTHER tenant's provider row (WITH CHECK tenant_id = app_current_tenant()).
func TestAdversarial_TenantCannotWriteOtherTenantRow(t *testing.T) {
	db := aiDB(t)
	a := aiTenant(t, db)
	b := aiTenant(t, db)
	err := db.WithTenant(context.Background(), a, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ai_provider (tenant_id, provider_kind, model) VALUES ($1, 'disabled', '')`, b)
		return e
	})
	if err == nil {
		t.Fatal("tenant A must NOT be able to write tenant B's provider row")
	}
}

// A tenant must not update the global row's key/endpoint out from under the platform (the widened UPDATE policy is
// system-only for the global row).
func TestAdversarial_TenantCannotUpdateGlobalRow(t *testing.T) {
	db := aiDB(t)
	tid := aiTenant(t, db)
	var updated int64
	err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE ai_provider SET provider_kind='disabled' WHERE tenant_id IS NULL`)
		if e == nil {
			updated = tag.RowsAffected()
		}
		return e
	})
	// RLS makes the global row invisible-for-write to a tenant: the UPDATE affects 0 rows (not an error, but no
	// effect) — the tenant cannot flip the platform default to disabled for everyone.
	if err == nil && updated != 0 {
		t.Fatalf("a tenant UPDATE must not modify the global row, affected=%d", updated)
	}
}

// A tenant reading provider config never sees another tenant's key ref (FORCE RLS on the row).
func TestAdversarial_TenantCannotReadOtherTenantKeyRef(t *testing.T) {
	db := aiDB(t)
	a := aiTenant(t, db)
	b := aiTenant(t, db)
	setProviderRow(t, db, a, KindAnthropic, "", "m", "c2VhbGVk") // A has a key ref
	// B's effective provider resolves to the GLOBAL default (anthropic), never A's row.
	row, _, err := NewRepository(db).ProviderConfig(context.Background(), b)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if !row.IsGlobal {
		t.Fatalf("tenant B must see the global row, not tenant A's; got isGlobal=%v key=%q", row.IsGlobal, row.APIKeyRef)
	}
	if row.APIKeyRef != "" {
		t.Fatal("tenant B must never see another tenant's api_key_ref")
	}
}

var _ = uuid.Nil // keep uuid imported if probes evolve
