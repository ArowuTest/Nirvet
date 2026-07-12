package asset

// #188 asset bulk-ingest landing round (DB-gated). Proves the new bulk input surface: valid rows import,
// partial-success (a bad row is reported, not fatal), the row-count + field-length caps, idempotent upsert-on-ref,
// and tenant isolation.

import (
	"context"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
)

func bulkSvc(t *testing.T) (*Service, auth.Principal, *database.DB) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "ab-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	p := auth.Principal{TenantID: tn.ID, UserID: uuid.New(), Email: "a@b.c"}
	return NewService(NewRepository(db), db), p, db
}

func TestAssetBulk_ImportsValidRows(t *testing.T) {
	svc, p, _ := bulkSvc(t)
	ctx := context.Background()
	items := []CreateInput{
		{Ref: "host:a1", Name: "A1", Kind: "host", Criticality: "high"},
		{Ref: "user:u1", Name: "U1", Kind: "user"},
		{Ref: "cloud:c1", Name: "C1", Kind: "cloud", Criticality: "critical"},
	}
	res, err := svc.BulkCreate(ctx, p, items)
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if res.Imported != 3 || res.Failed != 0 {
		t.Fatalf("expected 3 imported/0 failed, got %+v", res)
	}
	list, _ := svc.List(ctx, p.TenantID)
	if len(list) != 3 {
		t.Fatalf("expected 3 assets after import, got %d", len(list))
	}
}

func TestAssetBulk_PartialSuccess(t *testing.T) {
	svc, p, _ := bulkSvc(t)
	ctx := context.Background()
	items := []CreateInput{
		{Ref: "host:ok1", Name: "ok1", Kind: "host"},
		{Ref: "host:bad", Name: "bad", Kind: "toaster"}, // invalid kind → data error, recorded not fatal
		{Ref: "  ", Name: "noref"},                      // missing ref → data error
		{Ref: "host:ok2", Name: "ok2"},
	}
	res, err := svc.BulkCreate(ctx, p, items)
	if err != nil {
		t.Fatalf("bulk must not abort on a data error: %v", err)
	}
	if res.Imported != 2 || res.Failed != 2 {
		t.Fatalf("expected 2 imported/2 failed, got %+v", res)
	}
	if len(res.Failures) != 2 || res.Failures[0].Index != 1 || res.Failures[1].Index != 2 {
		t.Fatalf("failures must carry the offending row indices; got %+v", res.Failures)
	}
}

func TestAssetBulk_RowCapAndFieldGuard(t *testing.T) {
	svc, p, _ := bulkSvc(t)
	ctx := context.Background()
	// Row cap: 1001 rows → 400 before any import.
	tooMany := make([]CreateInput, maxBulkRows+1)
	for i := range tooMany {
		tooMany[i] = CreateInput{Ref: "host:x", Name: "x"}
	}
	if _, err := svc.BulkCreate(ctx, p, tooMany); err == nil {
		t.Fatal("expected a 400 for exceeding the row cap")
	}
	// Field guard: an over-long ref is recorded as a failure, not imported.
	res, err := svc.BulkCreate(ctx, p, []CreateInput{{Ref: strings.Repeat("h", maxFieldLen+1), Name: "big"}})
	if err != nil {
		t.Fatalf("field guard should be a per-row failure, not fatal: %v", err)
	}
	if res.Imported != 0 || res.Failed != 1 {
		t.Fatalf("an over-long ref must be a recorded failure; got %+v", res)
	}
}

func TestAssetBulk_IdempotentUpsert(t *testing.T) {
	svc, p, _ := bulkSvc(t)
	ctx := context.Background()
	items := []CreateInput{{Ref: "host:dup", Name: "v1", Kind: "host"}}
	_, _ = svc.BulkCreate(ctx, p, items)
	// Re-import the same ref (updated name) → upsert, not a duplicate.
	items[0].Name = "v2"
	if _, err := svc.BulkCreate(ctx, p, items); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	list, _ := svc.List(ctx, p.TenantID)
	if len(list) != 1 {
		t.Fatalf("upsert-on-ref must not duplicate; got %d assets", len(list))
	}
}

func TestAssetBulk_TenantIsolation(t *testing.T) {
	svc, pA, db := bulkSvc(t)
	ctx := context.Background()
	_, _ = svc.BulkCreate(ctx, pA, []CreateInput{{Ref: "host:a", Name: "a"}, {Ref: "host:b", Name: "b"}})
	tnB, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "abB-" + uuid.NewString()})
	if list, _ := svc.List(ctx, tnB.ID); len(list) != 0 {
		t.Fatalf("tenant B must see none of tenant A's bulk-imported assets; got %d", len(list))
	}
}
