package contentlifecycle

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func requirePersistenceDSNs(t *testing.T) (string, string) {
	t.Helper()
	app := os.Getenv("NIRVET_TEST_DATABASE_URL")
	owner := os.Getenv("NIRVET_OWNER_TEST_DATABASE_URL")
	if app == "" || owner == "" {
		t.Skip("content lifecycle persistence test requires app and owner DSNs")
	}
	return app, owner
}

func setTenant(t *testing.T, tx pgx.Tx, tenant uuid.UUID) {
	t.Helper()
	if _, err := tx.Exec(context.Background(), `SELECT set_config('app.current_tenant', $1, true)`, tenant.String()); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
}

func TestContentPersistence_RLSIsolationAndGlobalRead(t *testing.T) {
	appDSN, ownerDSN := requirePersistenceDSNs(t)
	ctx := context.Background()
	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	app, err := pgx.Connect(ctx, appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(ctx)

	tenantA := uuid.New()
	tenantB := uuid.New()
	publisher := "rls-test-" + uuid.NewString()
	defer func() {
		_, _ = owner.Exec(ctx, `DELETE FROM content_lifecycle_audit WHERE publisher_id=$1`, publisher)
		_, _ = owner.Exec(ctx, `DELETE FROM content_artifacts WHERE publisher_id=$1`, publisher)
		_, _ = owner.Exec(ctx, `DELETE FROM content_packages WHERE publisher_id=$1`, publisher)
	}()

	txA, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setTenant(t, txA, tenantA)
	var tenantPackage uuid.UUID
	err = txA.QueryRow(ctx, `
		INSERT INTO content_packages
		(tenant_id,publisher_id,content_type,version,scope,state,issued_at,expires_at,content_sha256,manifest_bytes,content_bytes,signature,imported_by)
		VALUES ($1,$2,'detection_rules',1,'tenant','quarantined',now(),now()+interval '1 day',$3,'{}','{}','x','importer-a')
		RETURNING id`, tenantA, publisher, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Scan(&tenantPackage)
	if err != nil {
		_ = txA.Rollback(ctx)
		t.Fatalf("tenant A insert: %v", err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	txB, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setTenant(t, txB, tenantB)
	var visible int
	if err := txB.QueryRow(ctx, `SELECT count(*) FROM content_packages WHERE id=$1`, tenantPackage).Scan(&visible); err != nil {
		_ = txB.Rollback(ctx)
		t.Fatal(err)
	}
	if visible != 0 {
		_ = txB.Rollback(ctx)
		t.Fatalf("tenant B saw tenant A package: count=%d", visible)
	}
	if _, err := txB.Exec(ctx, `
		INSERT INTO content_packages
		(tenant_id,publisher_id,content_type,version,scope,state,issued_at,expires_at,content_sha256,manifest_bytes,content_bytes,signature,imported_by)
		VALUES (NULL,$1,'detection_rules',2,'global','quarantined',now(),now()+interval '1 day',$2,'{}','{}','x','tenant-b')`,
		publisher, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err == nil {
		_ = txB.Rollback(ctx)
		t.Fatal("tenant runtime inserted global content; owner/padmin fence failed open")
	}
	_ = txB.Rollback(ctx)

	var globalPackage uuid.UUID
	err = owner.QueryRow(ctx, `
		INSERT INTO content_packages
		(tenant_id,publisher_id,content_type,version,scope,state,issued_at,expires_at,content_sha256,manifest_bytes,content_bytes,signature,imported_by)
		VALUES (NULL,$1,'detection_rules',3,'global','active',now(),now()+interval '1 day',$2,'{}','{}','x','padmin')
		RETURNING id`, publisher, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").Scan(&globalPackage)
	if err != nil {
		t.Fatalf("owner global insert: %v", err)
	}

	txA2, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setTenant(t, txA2, tenantA)
	if err := txA2.QueryRow(ctx, `SELECT count(*) FROM content_packages WHERE id=$1`, globalPackage).Scan(&visible); err != nil {
		_ = txA2.Rollback(ctx)
		t.Fatal(err)
	}
	if visible != 1 {
		_ = txA2.Rollback(ctx)
		t.Fatalf("tenant could not read operator global content: count=%d", visible)
	}
	if err := txA2.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestContentPersistence_SchemaHasForceRLSAndOwnerBypass(t *testing.T) {
	_, ownerDSN := requirePersistenceDSNs(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	for _, table := range []string{"content_packages", "content_artifacts", "content_lifecycle_audit"} {
		var enabled, forced, ownerBypass bool
		err := conn.QueryRow(ctx, `
			SELECT c.relrowsecurity, c.relforcerowsecurity,
			       EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname AND p.policyname='owner_bypass')
			FROM pg_class c WHERE c.oid=$1::regclass`, table).Scan(&enabled, &forced, &ownerBypass)
		if err != nil {
			t.Fatalf("inspect %s: %v", table, err)
		}
		if !enabled || !forced || !ownerBypass {
			t.Fatalf("%s RLS invariant: enabled=%v forced=%v owner_bypass=%v", table, enabled, forced, ownerBypass)
		}
	}
}
