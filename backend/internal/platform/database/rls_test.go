package database

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestRLSIsolation is the platform's crown-jewel security test: with the
// application (non-owner, FORCE ROW LEVEL SECURITY) role, one tenant can never
// see another tenant's rows. Requires a migrated DB; gated on the env var so it
// runs in CI and locally, skips otherwise.
//
//	NIRVET_TEST_DATABASE_URL=postgres://nirvet_app:nirvet_app@localhost:5433/nirvet?sslmode=disable go test ./internal/platform/database/ -run RLS
func TestRLSIsolation(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	tenantA, tenantB := uuid.New(), uuid.New()
	titleA := "rls-test-A-" + uuid.NewString()
	titleB := "rls-test-B-" + uuid.NewString()

	insert := func(tenant uuid.UUID, title string) {
		if err := db.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO alerts (id, title, severity) VALUES ($1,$2,'low')`, uuid.New(), title)
			return e
		}); err != nil {
			t.Fatalf("insert %s: %v", title, err)
		}
	}
	count := func(tenant uuid.UUID, title string) int {
		var n int
		if err := db.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE title=$1`, title).Scan(&n)
		}); err != nil {
			t.Fatalf("count %s: %v", title, err)
		}
		return n
	}
	cleanup := func(tenant uuid.UUID, title string) {
		_ = db.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `DELETE FROM alerts WHERE title=$1`, title)
			return e
		})
	}
	defer cleanup(tenantA, titleA)
	defer cleanup(tenantB, titleB)

	insert(tenantA, titleA)
	insert(tenantB, titleB)

	// Each tenant sees its own row.
	if got := count(tenantA, titleA); got != 1 {
		t.Fatalf("tenant A should see its own alert: got %d", got)
	}
	if got := count(tenantB, titleB); got != 1 {
		t.Fatalf("tenant B should see its own alert: got %d", got)
	}
	// Neither tenant can see the other's row — the isolation guarantee.
	if got := count(tenantA, titleB); got != 0 {
		t.Fatalf("SECURITY: tenant A leaked tenant B's alert (got %d)", got)
	}
	if got := count(tenantB, titleA); got != 0 {
		t.Fatalf("SECURITY: tenant B leaked tenant A's alert (got %d)", got)
	}
}

// TestNoTenantContextIsFailClosed verifies that without a tenant GUC set, RLS
// returns nothing (fail-closed) rather than leaking all rows.
func TestNoTenantContextIsFailClosed(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	tenant := uuid.New()
	title := "rls-failclosed-" + uuid.NewString()
	_ = db.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO alerts (id, title, severity) VALUES ($1,$2,'low')`, uuid.New(), title)
		return e
	})
	defer db.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM alerts WHERE title=$1`, title)
		return e
	})

	// WithSystem sets no tenant GUC; app_current_tenant() is NULL, so the RLS
	// policy matches no rows.
	var n int
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE title=$1`, title).Scan(&n)
	}); err != nil {
		t.Fatalf("system query: %v", err)
	}
	if n != 0 {
		t.Fatalf("SECURITY: without tenant context RLS must return 0 rows, got %d", n)
	}
}
