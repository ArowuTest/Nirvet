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

// --- external-audit Finding 1: idempotent-delete self-heal + deletion-attempt ledger ---

// flakyBlobs wraps a Store to inject Delete failures, simulating an object-store outage.
type flakyBlobs struct {
	blobstore.Store
	failDelete bool
}

func (f *flakyBlobs) Delete(ctx context.Context, uri string) error {
	if f.failDelete {
		return errTestBlobDelete
	}
	return f.Store.Delete(ctx, uri)
}

var errTestBlobDelete = pgErr("injected blob delete failure")

type pgErr string

func (e pgErr) Error() string { return string(e) }

func ledgerEntry(t *testing.T, db *database.DB, tid, id uuid.UUID) (blobDeleted, rowDeleted, exists bool) {
	t.Helper()
	_ = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT blob_deleted, row_deleted, true FROM retention_deletion_attempt WHERE raw_event_id=$1`, id).
			Scan(&blobDeleted, &rowDeleted, &exists)
	})
	return
}

func pendingMissing(t *testing.T, db *database.DB) int64 {
	t.Helper()
	var n int64
	_ = db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(rows_with_missing_blob,0) FROM retention_pending_summary()`).Scan(&n)
	})
	return n
}

// A row orphaned by a crash between blob delete and metadata delete (blob already gone, row still present)
// self-heals on the next sweep: blobstore.Delete is idempotent on a missing object, so the row is finally
// removed. This is the recovery from the exact failure the auditor described.
func TestRetention_OrphanedRowSelfHeals(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	p, tid := retTenant(t, db, 30)
	ctx := context.Background()
	_, _ = svc.SetPolicy(ctx, p, true, nil)
	id, uri := seedRaw(t, db, blobs, tid, oldT, true)
	if err := blobs.Delete(ctx, uri); err != nil { // post-failure state: blob deleted, metadata row still present
		t.Fatalf("pre-delete blob: %v", err)
	}
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rawExists(t, db, tid, id) {
		t.Fatal("orphaned row (blob already gone) must self-heal — the idempotent Delete lets the row be removed")
	}
}

// A blob-delete failure is fail-safe — the row AND its blob are both kept (never over-delete) — and is recorded
// in the deletion-attempt ledger; when the object store recovers, the next sweep completes and heals it.
func TestRetention_BlobDeleteFailureFailSafeThenHeals(t *testing.T) {
	db := retDB(t)
	local, err := blobstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore: %v", err)
	}
	flaky := &flakyBlobs{Store: local}
	svc := NewService(db, flaky)
	p, tid := retTenant(t, db, 30)
	ctx := context.Background()
	_, _ = svc.SetPolicy(ctx, p, true, nil)
	id, uri := seedRaw(t, db, flaky, tid, oldT, true)

	flaky.failDelete = true
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep with a failing blob delete must not error (fail-safe skip), got %v", err)
	}
	if !rawExists(t, db, tid, id) {
		t.Fatal("a blob-delete failure must KEEP the row (retained with its blob)")
	}
	if _, err := local.Get(ctx, uri); err != nil {
		t.Fatal("the blob must be retained with the row on a blob-delete failure")
	}
	if bd, _, ok := ledgerEntry(t, db, tid, id); !ok || bd {
		t.Fatalf("expected a ledger entry with blob_deleted=false; got exists=%v blob_deleted=%v", ok, bd)
	}

	flaky.failDelete = false // object store recovers
	if _, err := svc.SweepTenant(ctx, tid); err != nil {
		t.Fatalf("sweep after recovery: %v", err)
	}
	if rawExists(t, db, tid, id) {
		t.Fatal("the row must be deleted once the blob delete succeeds")
	}
}

// The ledger + cross-tenant summary make the "blob deleted, metadata delete failed" orphan observable and show
// it healing: an orphan recorded via recordAttempts is reported by retention_pending_summary; completing it
// clears the signal.
func TestRetention_LedgerReportsAndClearsOrphan(t *testing.T) {
	db := retDB(t)
	svc, blobs := retSvc(t, db)
	_, tid := retTenant(t, db, 30)
	ctx := context.Background()
	id, _ := seedRaw(t, db, blobs, tid, oldT, false)

	before := pendingMissing(t, db)
	svc.recordAttempts(ctx, tid, []uuid.UUID{id}, []string{"deadbeef"}, true) // blob gone, metadata row remains
	if got := pendingMissing(t, db) - before; got != 1 {
		t.Fatalf("retention_pending_summary rows_with_missing_blob delta = %d, want 1", got)
	}
	if bd, rd, ok := ledgerEntry(t, db, tid, id); !ok || !bd || rd {
		t.Fatalf("ledger should be blob_deleted=true,row_deleted=false; got ok=%v bd=%v rd=%v", ok, bd, rd)
	}
	svc.completeAttempts(ctx, tid, []uuid.UUID{id})
	if got := pendingMissing(t, db) - before; got != 0 {
		t.Fatalf("after completion the summary delta = %d, want 0 (healed)", got)
	}
}
