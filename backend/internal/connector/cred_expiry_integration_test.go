package connector

// #188 cred-expiry landing round (DB-gated on NIRVET_TEST_DATABASE_URL). Proves the reminder sweeper mirrors the
// SLA-breach guarantees: reminds a soon-expiring credential exactly ONCE (claim dedupe), skips one outside the
// window, re-reminds after a NEW expiry is set, and is cross-tenant (each claim tenant-scoped).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/ingestion"
	"github.com/ArowuTest/nirvet/internal/platform/blobstore"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/queue"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeEnq captures reminder enqueues (runs inside the claim tx).
type fakeEnq struct {
	mu    sync.Mutex
	calls []enqCall
}
type enqCall struct {
	tenantID         uuid.UUID
	channel, subject string
}

func (f *fakeEnq) EnqueueTx(_ context.Context, _ pgx.Tx, tenantID uuid.UUID, channel, _, subject, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, enqCall{tenantID, channel, subject})
	return nil
}

func credExpirySvc(t *testing.T) (*Service, *fakeEnq, *database.DB) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	blobs, _ := blobstore.NewLocal(t.TempDir())
	ingestSvc := ingestion.NewService(ingestion.NewRepository(db), queue.NewPostgres(db.Pool), nil, blobs)
	enq := &fakeEnq{}
	// No escalation resolver wired → the sweep falls back to the "log" channel (never silently unsent).
	svc := NewService(NewRepository(db), NewVault(cipher), ingestSvc).WithEnqueuer(enq)
	return svc, enq, db
}

func mkTenant(t *testing.T, ctx context.Context, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "ce-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

func mkConnector(t *testing.T, ctx context.Context, svc *Service, tid uuid.UUID) uuid.UUID {
	t.Helper()
	res, err := svc.Create(ctx, tid, CreateInput{Kind: KindMicrosoft365, Name: "m365-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}
	return res.Connector.ID
}

func (f *fakeEnq) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func TestCredExpiry_RemindsOnceThenIdempotent(t *testing.T) {
	svc, enq, db := credExpirySvc(t)
	ctx := context.Background()
	tid := mkTenant(t, ctx, db)
	id := mkConnector(t, ctx, svc, tid)
	now := time.Now()
	soon := now.Add(3 * 24 * time.Hour) // within the 14-day reminder window
	if err := svc.SetCredExpiry(ctx, tid, id, &soon); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	n, err := svc.SweepCredExpiry(ctx, now, 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 || enq.count() != 1 {
		t.Fatalf("expected exactly one reminder; sweep=%d enqueued=%d", n, enq.count())
	}
	if enq.calls[0].tenantID != tid || enq.calls[0].channel != "log" {
		t.Fatalf("reminder routed wrong: %+v (want tenant=%s channel=log)", enq.calls[0], tid)
	}
	// Second sweep: already reminded → no re-fire (claim marker holds).
	n2, _ := svc.SweepCredExpiry(ctx, now, 100)
	if n2 != 0 || enq.count() != 1 {
		t.Fatalf("reminder must be exactly-once; second sweep=%d total enqueued=%d", n2, enq.count())
	}
}

func TestCredExpiry_OutsideWindowNotReminded(t *testing.T) {
	svc, enq, db := credExpirySvc(t)
	ctx := context.Background()
	tid := mkTenant(t, ctx, db)
	id := mkConnector(t, ctx, svc, tid)
	now := time.Now()
	far := now.Add(60 * 24 * time.Hour) // well beyond the 14-day window
	if err := svc.SetCredExpiry(ctx, tid, id, &far); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	if n, _ := svc.SweepCredExpiry(ctx, now, 100); n != 0 || enq.count() != 0 {
		t.Fatalf("a far-future expiry must not be reminded; sweep=%d enqueued=%d", n, enq.count())
	}
}

func TestCredExpiry_ResetsOnNewExpiry(t *testing.T) {
	svc, enq, db := credExpirySvc(t)
	ctx := context.Background()
	tid := mkTenant(t, ctx, db)
	id := mkConnector(t, ctx, svc, tid)
	now := time.Now()
	first := now.Add(2 * 24 * time.Hour)
	_ = svc.SetCredExpiry(ctx, tid, id, &first)
	if n, _ := svc.SweepCredExpiry(ctx, now, 100); n != 1 {
		t.Fatalf("first reminder should fire, got %d", n)
	}
	// Credential renewed → a NEW expiry is set; the marker resets, so it is reminded again.
	second := now.Add(5 * 24 * time.Hour)
	if err := svc.SetCredExpiry(ctx, tid, id, &second); err != nil {
		t.Fatalf("reset expiry: %v", err)
	}
	if n, _ := svc.SweepCredExpiry(ctx, now, 100); n != 1 || enq.count() != 2 {
		t.Fatalf("a renewed-then-re-expiring credential must be reminded again; sweep=%d total=%d", n, enq.count())
	}
}

func TestCredExpiry_CrossTenant(t *testing.T) {
	svc, enq, db := credExpirySvc(t)
	ctx := context.Background()
	tA, tB := mkTenant(t, ctx, db), mkTenant(t, ctx, db)
	idA, idB := mkConnector(t, ctx, svc, tA), mkConnector(t, ctx, svc, tB)
	now := time.Now()
	soon := now.Add(4 * 24 * time.Hour)
	_ = svc.SetCredExpiry(ctx, tA, idA, &soon)
	_ = svc.SetCredExpiry(ctx, tB, idB, &soon)
	n, err := svc.SweepCredExpiry(ctx, now, 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("both tenants' expiring connectors should be reminded, got %d", n)
	}
	// Each reminder went to its OWN tenant (claim is tenant-scoped).
	seen := map[uuid.UUID]bool{}
	for _, c := range enq.calls {
		seen[c.tenantID] = true
	}
	if !seen[tA] || !seen[tB] {
		t.Fatalf("each reminder must be tenant-scoped; saw %+v (want %s and %s)", seen, tA, tB)
	}
}
