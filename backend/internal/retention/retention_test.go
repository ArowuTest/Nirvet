package retention

// §6.14 #188 HEAVY-3 retention landing round (DB-gated). The reviewer's required tests: legal-hold SKIPS deletion;
// a missing/zero window KEEPS (fail-safe); a disabled policy only DRY-RUNS (counts, never deletes); an enabled
// policy deletes telemetry past the cutoff AND deletes the raw payload BLOB with the row, while keeping recent
// data and never touching non-telemetry (alerts).

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func retDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func retSvc(t *testing.T, db *database.DB) (*Service, blobstore.Store) {
	t.Helper()
	blobs, err := blobstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore: %v", err)
	}
	return NewService(db, blobs), blobs
}

func retTenant(t *testing.T, db *database.DB, retentionDays int) (auth.Principal, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "ret-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if retentionDays > 0 {
		if err := db.WithTenant(ctx, tn.ID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx,
				`INSERT INTO entitlements (tenant_id, tier, events_per_day, max_integrations, retention_days, ir_hours)
				 VALUES ($1,'standard',100000,10,$2,24) ON CONFLICT (tenant_id) DO UPDATE SET retention_days=EXCLUDED.retention_days`,
				tn.ID, retentionDays)
			return e
		}); err != nil {
			t.Fatalf("entitlement: %v", err)
		}
	}
	return auth.Principal{TenantID: tn.ID, UserID: uuid.New(), Email: "a@ret", Role: auth.RolePlatformAdmin}, tn.ID
}

// seedRaw inserts a raw_events row (optionally with a real blob) at received_at, returning the id + blob uri.
func seedRaw(t *testing.T, db *database.DB, blobs blobstore.Store, tid uuid.UUID, receivedAt time.Time, withBlob bool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	blobURI := ""
	if withBlob {
		uri, err := blobs.Put(ctx, tid, "raw/"+id.String()+".json", []byte(`{"raw":"payload"}`))
		if err != nil {
			t.Fatalf("blob put: %v", err)
		}
		blobURI = uri
	}
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO raw_events (id, tenant_id, source, dedupe_key, checksum, payload, blob_uri, received_at)
			 VALUES ($1,$2,'test',$3,'ck','\x00'::bytea,$4,$5)`,
			id, tid, "dk-"+id.String(), blobURI, receivedAt)
		return e
	}); err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	return id, blobURI
}

func rawExists(t *testing.T, db *database.DB, tid, id uuid.UUID) bool {
	t.Helper()
	var n int
	_ = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM raw_events WHERE id=$1`, id).Scan(&n)
	})
	return n == 1
}

var oldT = time.Now().Add(-60 * 24 * time.Hour)
var recentT = time.Now().Add(-1 * 24 * time.Hour)

// Legal hold skips deletion entirely, even with an enabled policy and old data.
func TestRetention_LegalHoldSkips(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 30)
	ctx := context.Background()
	if _, err := svc.SetPolicy(ctx, p, true, nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	old, _ := seedRaw(t, db, blobs, tid, oldT, false)
	// Put the tenant on legal hold.
	_ = db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET legal_hold=true WHERE id=$1`, tid)
		return e
	})
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !rawExists(t, db, tid, old) {
		t.Fatal("legal hold must preserve telemetry — the old row was deleted")
	}
}

// A missing/zero retention window keeps everything (fail-safe), even with deletion enabled.
func TestRetention_FailSafeKeepsNoWindow(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 0) // no entitlement retention window
	ctx := context.Background()
	_, _ = svc.SetPolicy(ctx, p, true, nil)
	old, _ := seedRaw(t, db, blobs, tid, oldT, false)
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !rawExists(t, db, tid, old) {
		t.Fatal("a missing retention window must KEEP (fail-safe) — the old row was deleted")
	}
}

// A disabled policy only dry-runs: nothing deleted, a dry-run log row records the candidate count.
func TestRetention_DisabledDryRun(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 30) // entitlement window present, policy DISABLED (default)
	ctx := context.Background()
	old, _ := seedRaw(t, db, blobs, tid, oldT, false)
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !rawExists(t, db, tid, old) {
		t.Fatal("a disabled policy must NOT delete — the old row was deleted")
	}
	sweeps, _ := svc.ListSweeps(ctx, p, 50)
	var sawDryRunCandidate bool
	for _, s := range sweeps {
		if s.DryRun && s.Store == "raw_events" && s.CandidateCount >= 1 && s.DeletedCount == 0 {
			sawDryRunCandidate = true
		}
	}
	if !sawDryRunCandidate {
		t.Fatalf("expected a dry-run log row with a candidate count and 0 deleted; got %+v", sweeps)
	}
}

// Enabled: deletes telemetry past the cutoff AND its payload blob; keeps recent data.
func TestRetention_EnabledDeletesPastCutoffWithBlob(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 30)
	ctx := context.Background()
	_, _ = svc.SetPolicy(ctx, p, true, nil)

	old, oldBlob := seedRaw(t, db, blobs, tid, oldT, true)
	recent, _ := seedRaw(t, db, blobs, tid, recentT, true)

	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rawExists(t, db, tid, old) {
		t.Fatal("the old row (past cutoff) must be deleted")
	}
	if !rawExists(t, db, tid, recent) {
		t.Fatal("the recent row (within window) must be kept")
	}
	// The old row's payload blob must be gone with the row (else it lingers past retention).
	if _, err := blobs.Get(ctx, oldBlob); err == nil {
		t.Fatal("the old row's payload blob must be deleted with the row")
	}
}

// Retention never touches non-telemetry (an old alert row survives).
func TestRetention_TelemetryOnly(t *testing.T) {
	db := retDB(t)
	svc, _ := retSvc(t, db)
	p, tid := retTenant(t, db, 30)
	ctx := context.Background()
	_, _ = svc.SetPolicy(ctx, p, true, nil)

	alertID := uuid.New()
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO alerts (id, tenant_id, title, severity, created_at) VALUES ($1,$2,'old','high',$3)`, alertID, tid, oldT)
		return e
	}); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var n int
	_ = db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE id=$1`, alertID).Scan(&n)
	})
	if n != 1 {
		t.Fatal("retention must NOT delete alerts (telemetry-only)")
	}
}
