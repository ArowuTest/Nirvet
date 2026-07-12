package soar

// §6.11 #188 HEAVY-2 (sub-commit 1) — the single-use, run-bound approval-link primitive (DB-gated). The replay
// fix: a link consumes AT MOST ONCE, only while unexpired, and returns the BOUND tenant + run; a replay, an
// expired link, or an unknown token yields not-found.

import (
	"context"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func linkDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func linkTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "lnk-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

// A link consumes exactly once (returning the bound tenant+run), and a replay is rejected.
func TestApprovalLink_SingleUseAndRunBound(t *testing.T) {
	db := linkDB(t)
	repo := NewRepository(db)
	tid := linkTenant(t, db)
	runID := uuid.New()
	ctx := context.Background()

	raw, err := newApprovalToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if err := repo.insertApprovalLink(ctx, tid, runID, hashToken(raw), time.Now().Add(time.Hour), uuid.New()); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// First consume → the bound tenant + run.
	gotT, gotR, err := repo.consumeApprovalLink(ctx, hashToken(raw))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if gotT != tid || gotR != runID {
		t.Fatalf("consume returned wrong binding: tenant=%s run=%s", gotT, gotR)
	}
	// Replay → rejected (single-use).
	if _, _, err := repo.consumeApprovalLink(ctx, hashToken(raw)); err == nil {
		t.Fatal("a consumed link must NOT be consumable again (replay)")
	}
}

// An expired link cannot be consumed; an unknown token cannot be consumed.
func TestApprovalLink_ExpiredAndUnknownRejected(t *testing.T) {
	db := linkDB(t)
	repo := NewRepository(db)
	tid := linkTenant(t, db)
	ctx := context.Background()

	rawExpired, _ := newApprovalToken()
	if err := repo.insertApprovalLink(ctx, tid, uuid.New(), hashToken(rawExpired), time.Now().Add(-time.Minute), uuid.New()); err != nil {
		t.Fatalf("insert expired: %v", err)
	}
	if _, _, err := repo.consumeApprovalLink(ctx, hashToken(rawExpired)); err == nil {
		t.Fatal("an expired link must NOT be consumable")
	}
	rawUnknown, _ := newApprovalToken()
	if _, _, err := repo.consumeApprovalLink(ctx, hashToken(rawUnknown)); err == nil {
		t.Fatal("an unknown token must NOT be consumable")
	}
}

// The raw token is never stored — only its hash — so a DB read cannot recover a usable link.
func TestApprovalLink_RawTokenNotStored(t *testing.T) {
	db := linkDB(t)
	repo := NewRepository(db)
	tid := linkTenant(t, db)
	ctx := context.Background()

	raw, _ := newApprovalToken()
	if err := repo.insertApprovalLink(ctx, tid, uuid.New(), hashToken(raw), time.Now().Add(time.Hour), uuid.New()); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var stored string
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT token_hash FROM approval_link WHERE tenant_id=$1`, tid).Scan(&stored)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if stored == raw {
		t.Fatal("the raw token must never be stored (only its hash)")
	}
	if stored != hashToken(raw) {
		t.Fatalf("stored value must be the hash of the token")
	}
}
