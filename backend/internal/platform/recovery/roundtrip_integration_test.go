package recovery

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var recoveryTenantA = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
var recoveryTenantB = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
var recoveryIncidentA = uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
var recoveryIncidentB = uuid.MustParse("bbbbbbbb-0000-0000-0000-000000000001")

func TestRecoveryRoundTrip_RestoredDataIsolationAuditAndFunctionalJourney(t *testing.T) {
	ownerDSN := os.Getenv("NIRVET_RESTORED_OWNER_DATABASE_URL")
	appDSN := os.Getenv("NIRVET_RESTORED_APP_DATABASE_URL")
	if ownerDSN == "" || appDSN == "" {
		t.Skip("restored database DSNs not set")
	}
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	app, err := pgxpool.New(ctx, appDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	validation, err := ValidateRestoredPostgres(ctx, owner)
	if err != nil {
		t.Fatalf("restored postgres invariants failed: %v", err)
	}
	if validation.IntegrityEvidence == "" || validation.SecurityEvidence == "" || validation.TenantEvidence == "" {
		t.Fatal("restored postgres validation returned incomplete evidence")
	}
	if err := validateRoundTripMarkers(ctx, owner); err != nil {
		t.Fatal(err)
	}

	assertTenantIncidentView(t, ctx, app, recoveryTenantA, recoveryIncidentA, recoveryIncidentB)
	assertTenantIncidentView(t, ctx, app, recoveryTenantB, recoveryIncidentB, recoveryIncidentA)
	assertAuditContinuityAndImmutability(t, ctx, owner, app)
	assertFunctionalRestoredJourney(t, ctx, app)
}

func TestRecoveryRoundTrip_PartialRestoreCorruptionIsRefused(t *testing.T) {
	ownerDSN := os.Getenv("NIRVET_RESTORED_OWNER_DATABASE_URL")
	if ownerDSN == "" {
		t.Skip("restored owner database DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM incidents WHERE id=$1`, recoveryIncidentB); err != nil {
		t.Fatal(err)
	}
	if err := validateRoundTripMarkersQuerier(ctx, tx); err == nil || !strings.Contains(err.Error(), "incident markers") {
		t.Fatalf("silently truncated restore was not refused: %v", err)
	}
}

func TestRecoveryRoundTrip_CrossTenantRewriteAndAuditGapAreRefused(t *testing.T) {
	ownerDSN := os.Getenv("NIRVET_RESTORED_OWNER_DATABASE_URL")
	if ownerDSN == "" {
		t.Skip("restored owner database DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	t.Run("cross tenant rewrite", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `UPDATE incidents SET tenant_id=$1 WHERE id=$2`, recoveryTenantA, recoveryIncidentB); err != nil {
			t.Fatal(err)
		}
		if err := validateRoundTripMarkersQuerier(ctx, tx); err == nil || !strings.Contains(err.Error(), "tenant ownership") {
			t.Fatalf("cross-tenant rewrite was not refused: %v", err)
		}
	})

	t.Run("audit seam gap", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE request_id='recovery-seed-b'`); err != nil {
			t.Fatal(err)
		}
		if err := validateRoundTripMarkersQuerier(ctx, tx); err == nil || !strings.Contains(err.Error(), "audit markers") {
			t.Fatalf("audit seam gap was not refused: %v", err)
		}
	})
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func validateRoundTripMarkers(ctx context.Context, pool *pgxpool.Pool) error {
	return validateRoundTripMarkersQuerier(ctx, pool)
}

func validateRoundTripMarkersQuerier(ctx context.Context, q rowQuerier) error {
	var tenants, incidents, audits, ownership int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id IN ($1,$2)`, recoveryTenantA, recoveryTenantB).Scan(&tenants); err != nil {
		return fmt.Errorf("recovery: tenant markers: %w", err)
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id IN ($1,$2)`, recoveryIncidentA, recoveryIncidentB).Scan(&incidents); err != nil {
		return fmt.Errorf("recovery: incident markers: %w", err)
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE (id=$1 AND tenant_id=$2) OR (id=$3 AND tenant_id=$4)`, recoveryIncidentA, recoveryTenantA, recoveryIncidentB, recoveryTenantB).Scan(&ownership); err != nil {
		return fmt.Errorf("recovery: tenant ownership markers: %w", err)
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE request_id IN ('recovery-seed-a','recovery-seed-b')`).Scan(&audits); err != nil {
		return fmt.Errorf("recovery: audit markers: %w", err)
	}
	if tenants != 2 {
		return fmt.Errorf("recovery: tenant markers incomplete: got %d want 2", tenants)
	}
	if incidents != 2 {
		return fmt.Errorf("recovery: incident markers incomplete: got %d want 2", incidents)
	}
	if ownership != 2 {
		return fmt.Errorf("recovery: tenant ownership markers incomplete: got %d want 2", ownership)
	}
	if audits != 2 {
		return fmt.Errorf("recovery: audit markers incomplete: got %d want 2", audits)
	}
	return nil
}

func assertTenantIncidentView(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, visibleID, hiddenID uuid.UUID) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id=$1`, visibleID).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	var hidden int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id=$1`, hiddenID).Scan(&hidden); err != nil {
		t.Fatal(err)
	}
	if visible != 1 || hidden != 0 {
		t.Fatalf("tenant isolation failed for %s: visible=%d hidden=%d", tenantID, visible, hidden)
	}
}

func assertAuditContinuityAndImmutability(t *testing.T, ctx context.Context, owner, app *pgxpool.Pool) {
	t.Helper()
	var minID, maxID int64
	if err := owner.QueryRow(ctx, `SELECT min(id), max(id) FROM audit_log WHERE request_id IN ('recovery-seed-a','recovery-seed-b')`).Scan(&minID, &maxID); err != nil {
		t.Fatal(err)
	}
	if minID <= 0 || maxID < minID {
		t.Fatalf("invalid restored audit seam ids: %d..%d", minID, maxID)
	}
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, recoveryTenantA.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_log SET action='tampered' WHERE request_id='recovery-seed-a'`); err == nil {
		t.Fatal("restored audit log accepted an UPDATE")
	}
}

func assertFunctionalRestoredJourney(t *testing.T, ctx context.Context, app *pgxpool.Pool) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, recoveryTenantA.String()); err != nil {
		t.Fatal(err)
	}
	journeyID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO incidents (id,title,severity,category,stage) VALUES ($1,'recovery functional journey','low','recovery','new')`, journeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log (action,target,request_id) VALUES ('recovery.functional','incident:'||$1,'recovery-functional')`, journeyID.String()); err != nil {
		t.Fatal(err)
	}
	var incidentCount, auditCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE id=$1`, journeyID).Scan(&incidentCount); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE request_id='recovery-functional'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if incidentCount != 1 || auditCount != 1 {
		t.Fatalf("restored functional journey incomplete: incident=%d audit=%d", incidentCount, auditCount)
	}
}
