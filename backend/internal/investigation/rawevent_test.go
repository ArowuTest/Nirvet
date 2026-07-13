package investigation

// §6.9 #188 — get-raw-event landing round (DB-gated). The untransformed payload is the most sensitive read, so the
// probes are: it returns the real payload AND records a fail-closed read-audit (kind=raw_event); a foreign tenant
// gets not-found (RLS); a missing raw id is not-found.

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

func rawDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func rawTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "raw-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func seedRawEvent(t *testing.T, db *database.DB, blobs blobstore.Store, tid uuid.UUID, payload []byte) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	uri, err := blobs.Put(ctx, tid, "raw/"+id.String()+".json", payload)
	if err != nil {
		t.Fatalf("blob put: %v", err)
	}
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO raw_events (id, tenant_id, source, dedupe_key, checksum, payload, blob_uri, received_at)
			 VALUES ($1,$2,'test',$3,'ck','\x00'::bytea,$4,$5)`,
			id, tid, "dk-"+id.String(), uri, time.Now())
		return e
	}); err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	return id
}

func rawService(t *testing.T, db *database.DB) (*Service, blobstore.Store) {
	t.Helper()
	blobs, err := blobstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore: %v", err)
	}
	return NewService(NewRepository(db)).WithRawStore(blobs), blobs
}

// The owning tenant gets the real payload AND a read-audit row is written (fail-closed).
func TestRawEvent_ReturnsPayloadAndAudits(t *testing.T) {
	db := rawDB(t)
	svc, blobs := rawService(t, db)
	tid := rawTenant(t, db)
	ctx := context.Background()
	want := []byte(`{"raw":"secret-telemetry"}`)
	id := seedRawEvent(t, db, blobs, tid, want)
	p := auth.Principal{TenantID: tid, UserID: uuid.New(), Email: "a@raw", Role: auth.RoleSOCManager}

	raw, err := svc.GetRawEvent(ctx, p, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(raw.Payload) != string(want) {
		t.Fatalf("payload mismatch: got %q", raw.Payload)
	}
	var n int
	_ = db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM investigation_query_audit WHERE tenant_id=$1 AND kind='raw_event'`, tid).Scan(&n)
	})
	if n != 1 {
		t.Fatalf("expected exactly one raw_event read-audit row; got %d", n)
	}
}

// A different tenant cannot read another tenant's raw event (RLS → not-found).
func TestRawEvent_TenantIsolation(t *testing.T) {
	db := rawDB(t)
	svc, blobs := rawService(t, db)
	a := rawTenant(t, db)
	b := rawTenant(t, db)
	ctx := context.Background()
	id := seedRawEvent(t, db, blobs, a, []byte(`{"raw":"a-only"}`))

	pb := auth.Principal{TenantID: b, UserID: uuid.New(), Email: "b@raw", Role: auth.RoleSOCManager}
	if _, err := svc.GetRawEvent(ctx, pb, id); err == nil {
		t.Fatal("a different tenant must NOT read another tenant's raw event (RLS)")
	}
	// No cross-tenant audit leak: tenant B recorded no raw_event access (its lookup found nothing).
	var n int
	_ = db.WithTenant(ctx, b, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM investigation_query_audit WHERE tenant_id=$1 AND kind='raw_event'`, b).Scan(&n)
	})
	if n != 0 {
		t.Fatalf("a foreign-tenant miss must not audit an access; got %d", n)
	}
}

// An unknown raw id is not-found (never a 500).
func TestRawEvent_UnknownNotFound(t *testing.T) {
	db := rawDB(t)
	svc, _ := rawService(t, db)
	tid := rawTenant(t, db)
	p := auth.Principal{TenantID: tid, UserID: uuid.New(), Email: "a@raw", Role: auth.RoleSOCManager}
	if _, err := svc.GetRawEvent(context.Background(), p, uuid.New()); err == nil {
		t.Fatal("an unknown raw event id must be not-found")
	}
}
