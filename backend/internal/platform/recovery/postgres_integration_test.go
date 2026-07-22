package recovery

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateRestoredPostgres_RealDatabaseAndRLSCorruptionControl(t *testing.T) {
	dsn := os.Getenv("NIRVET_OWNER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIRVET_OWNER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	if _, err := ValidateRestoredPostgres(ctx, pool); err != nil {
		t.Fatalf("sound restored schema did not validate: %v", err)
	}

	name := "recovery_rls_probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := quoteIdentifier(name)
	if _, err := pool.Exec(ctx, `CREATE TABLE `+quoted+` (id uuid PRIMARY KEY, tenant_id uuid NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS `+quoted) }()
	if _, err := pool.Exec(ctx, `ALTER TABLE `+quoted+` ENABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE `+quoted+` FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	// Deliberately omit owner_bypass. The restored-schema validator must refuse
	// certification; this proves the security assertion is not decorative.
	if _, err := ValidateRestoredPostgres(ctx, pool); err == nil || !strings.Contains(err.Error(), name+":owner-bypass-missing") {
		t.Fatalf("RLS corruption control was not detected: %v", err)
	}
}
