package soar

// §6.11 completion reconciler R-1 — the repo layer: G-2 (only rows we caused are listed), G-1 (the bare
// action id, not the display connector_ref), and the confirm/fail lifecycle incl. reverse-exclusion of a
// failed containment. Internal test (package soar) so it can drive the unexported repo directly.

import (
	"context"
	"fmt"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestReconcileRepo_G1G2AndLifecycle(t *testing.T) {
	dsn := testsupport.RequireDSN(t)
	ctx := context.Background()
	db, err := database.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	repo := NewRepository(db)
	tn, _ := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "rec-" + uuid.NewString()})
	tid := tn.ID

	// insert an 'executed' connector row. connector_ref carries the DISPLAY string (as a crash-resumed row
	// would); prior_state carries the bare action_id (G-1) + the ownership flag (G-2).
	insert := func(runID uuid.UUID, changed bool, actionID string) {
		prior := fmt.Sprintf(`{"changed":%v,"action_id":%q,"machine_id":"m1"}`, changed, actionID)
		if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx,
				`INSERT INTO soar_action_execution
				   (tenant_id, run_id, step_index, action_key, connector_key, target, status, risk_class, connector_ref, prior_state, claimed_at)
				 VALUES ($1,$2,0,'isolate_endpoint','defender','host:h','executed','high',$3,$4::jsonb, now() - interval '5 minutes')`,
				tid, runID, "own-isolate:"+actionID, prior)
			return e
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	ownRun, foreignRun := uuid.New(), uuid.New()
	insert(ownRun, true, "iso-own-1")      // ours (changed=true)
	insert(foreignRun, false, "iso-fgn-1") // foreign no-op (changed=false) — G-2 must exclude

	// G-2: only the own row is listed. G-1: it carries the bare action id, not "own-isolate:...".
	got, err := repo.unconfirmedExecutions(ctx, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("G-2: expected only the own row, got %d", len(got))
	}
	if got[0].ActionID != "iso-own-1" {
		t.Fatalf("G-1: expected bare action_id 'iso-own-1', got %q", got[0].ActionID)
	}
	if got[0].AgeSecs < 60 {
		t.Fatalf("age should be ~300s, got %d", got[0].AgeSecs)
	}

	// Confirm removes it from the poll list.
	if err := repo.markConfirmed(ctx, tid, got[0].ID, "Succeeded"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if again, _ := repo.unconfirmedExecutions(ctx, 0); len(again) != 0 {
		t.Fatalf("confirmed row must not relist, got %d", len(again))
	}

	// A failed containment flips executed→failed and is thereby EXCLUDED from reverse (nothing to undo).
	failRun := uuid.New()
	insert(failRun, true, "iso-fail-1")
	list, _ := repo.unconfirmedExecutions(ctx, 0)
	var failID uuid.UUID
	for _, u := range list {
		if u.ActionID == "iso-fail-1" {
			failID = u.ID
		}
	}
	if failID == uuid.Nil {
		t.Fatal("fail row not listed before failing it")
	}
	if err := repo.markContainmentFailed(ctx, tid, failID, "Failed"); err != nil {
		t.Fatalf("markContainmentFailed: %v", err)
	}
	if rev, _ := repo.listReversibleExecutions(ctx, tid, failRun); len(rev) != 0 {
		t.Fatalf("failed containment must be excluded from reverse, got %d", len(rev))
	}
}
