package alert_test

// Atomicity of the *Tx mutation paths (fleet cross-tenant assign/disposition audit). The invariant the fleet
// write path depends on: the mutation and its post-mutation callback (the target-tenant audit row) commit in ONE
// transaction. So a callback failure MUST roll the mutation back — a cross-tenant write is never applied with a
// dropped audit row. These tests lock that by injecting a failing callback and asserting the alert is unchanged.
// Restore the pre-fix behaviour (mutation + audit in separate txs) and both go red.

import (
	"context"
	"errors"
	"testing"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func txDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func seedAlert(t *testing.T, db *database.DB, tid uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO alerts (id, title, severity, status, source) VALUES ($1,'tx','high','new','test')`, id)
		return e
	}); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return id
}

func statusAndAssignee(t *testing.T, db *database.DB, tid, id uuid.UUID) (string, *uuid.UUID) {
	t.Helper()
	var status string
	var assignee *uuid.UUID
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, assignee_id FROM alerts WHERE id=$1`, id).Scan(&status, &assignee)
	}); err != nil {
		t.Fatalf("read alert: %v", err)
	}
	return status, assignee
}

func mkTenant(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "alerttx-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return tn.ID
}

var errCallback = errors.New("injected post-tx failure")

func TestAssignTx_CallbackFailureRollsBackMutation(t *testing.T) {
	db := txDB(t)
	repo := alert.NewRepository(db)
	ctx := context.Background()

	tid := mkTenant(t, db)
	id := seedAlert(t, db, tid)
	assignee := uuid.New()

	err := repo.AssignTx(ctx, tid, id, assignee, func(ctx context.Context, tx pgx.Tx) error {
		return errCallback // the audit row "fails" — the whole tx must roll back
	})
	if !errors.Is(err, errCallback) {
		t.Fatalf("AssignTx must surface the callback error, got %v", err)
	}

	// The assignment must NOT have landed — it shared the failed transaction.
	status, got := statusAndAssignee(t, db, tid, id)
	if status != "new" || got != nil {
		t.Fatalf("assign must roll back on audit failure: status=%q assignee=%v (want new/nil)", status, got)
	}

	// Sanity: with no callback, the assign lands.
	if err := repo.AssignTx(ctx, tid, id, assignee, nil); err != nil {
		t.Fatalf("clean assign: %v", err)
	}
	if status, got := statusAndAssignee(t, db, tid, id); status != "assigned" || got == nil || *got != assignee {
		t.Fatalf("clean assign must land: status=%q assignee=%v", status, got)
	}
}

func TestCloseTx_CallbackFailureRollsBackMutation(t *testing.T) {
	db := txDB(t)
	repo := alert.NewRepository(db)
	ctx := context.Background()

	tid := mkTenant(t, db)
	id := seedAlert(t, db, tid)

	err := repo.CloseTx(ctx, tid, id, func(ctx context.Context, tx pgx.Tx) error {
		return errCallback
	})
	if !errors.Is(err, errCallback) {
		t.Fatalf("CloseTx must surface the callback error, got %v", err)
	}

	if status, _ := statusAndAssignee(t, db, tid, id); status != "new" {
		t.Fatalf("close must roll back on audit failure: status=%q (want new)", status)
	}

	// Sanity: with no callback, the close lands.
	if err := repo.CloseTx(ctx, tid, id, nil); err != nil {
		t.Fatalf("clean close: %v", err)
	}
	if status, _ := statusAndAssignee(t, db, tid, id); status != "closed" {
		t.Fatalf("clean close must land: status=%q", status)
	}
}
