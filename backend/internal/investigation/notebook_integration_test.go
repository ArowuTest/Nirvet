package investigation_test

// B2 investigation notebooks — DB-gated integration test. Covers the notebook lifecycle (create → add note +
// query cells → get in order → update → move → delete) and ownership isolation (a peer in the same tenant cannot
// read or mutate another analyst's private notebook). Skips when no test DSN is set.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/investigation"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func TestNotebooks_LifecycleAndIsolation(t *testing.T) {
	ctx := context.Background()
	db, err := database.Connect(ctx, testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "nb-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	svc := investigation.NewService(investigation.NewRepository(db))

	analyst := auth.Principal{UserID: uuid.New(), TenantID: tn.ID, Email: "a@corp.test"}
	peer := auth.Principal{UserID: uuid.New(), TenantID: tn.ID, Email: "b@corp.test"}

	nb, err := svc.CreateNotebook(ctx, analyst, "host-01 investigation", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	note, err := svc.AddCell(ctx, analyst, nb.ID, "note", "initial triage notes")
	if err != nil {
		t.Fatalf("add note: %v", err)
	}
	query, err := svc.AddCell(ctx, analyst, nb.ID, "query", "source = entra_id AND outcome = failure")
	if err != nil {
		t.Fatalf("add query: %v", err)
	}

	// Get returns both cells in position order (note first, query second).
	_, cells, err := svc.GetNotebook(ctx, analyst, nb.ID)
	if err != nil || len(cells) != 2 {
		t.Fatalf("get: err=%v cells=%d", err, len(cells))
	}
	if cells[0].ID != note.ID || cells[1].ID != query.ID {
		t.Fatalf("cells out of order: %+v", cells)
	}

	// Update a cell.
	if err := svc.UpdateCell(ctx, analyst, nb.ID, note.ID, "updated triage notes"); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Move the query cell up → it becomes first.
	if err := svc.MoveCell(ctx, analyst, nb.ID, query.ID, "up"); err != nil {
		t.Fatalf("move: %v", err)
	}
	_, cells, _ = svc.GetNotebook(ctx, analyst, nb.ID)
	if cells[0].ID != query.ID {
		t.Fatalf("move up failed, first cell = %s", cells[0].ID)
	}

	// Delete the note cell → one cell remains.
	if err := svc.DeleteCell(ctx, analyst, nb.ID, note.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, cells, _ = svc.GetNotebook(ctx, analyst, nb.ID)
	if len(cells) != 1 {
		t.Fatalf("after delete want 1 cell, got %d", len(cells))
	}

	// Ownership isolation: a peer cannot read or mutate the analyst's private notebook.
	if _, _, err := svc.GetNotebook(ctx, peer, nb.ID); err == nil {
		t.Fatal("peer must NOT read another analyst's notebook")
	}
	if _, err := svc.AddCell(ctx, peer, nb.ID, "note", "sneaky"); err == nil {
		t.Fatal("peer must NOT add a cell to another analyst's notebook")
	}
	if err := svc.DeleteCell(ctx, peer, nb.ID, query.ID); err == nil {
		t.Fatal("peer must NOT delete a cell in another analyst's notebook")
	}

	// Each analyst sees only their own notebooks.
	if mine, _ := svc.ListNotebooks(ctx, analyst); len(mine) != 1 {
		t.Fatalf("analyst should have 1 notebook, got %d", len(mine))
	}
	if theirs, _ := svc.ListNotebooks(ctx, peer); len(theirs) != 0 {
		t.Fatalf("peer should have 0 notebooks, got %d", len(theirs))
	}
}
