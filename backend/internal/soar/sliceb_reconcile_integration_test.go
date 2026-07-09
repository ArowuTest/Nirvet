package soar_test

// §6.11 completion reconciler R-4 — the adversarial suite: the real Defender Actioner + mock MDE + a counting
// alerter driven through the REAL Supervisor.ReconcileOnce. Proves the D-3 terminal-state table + G-1/G-2 +
// the read-only-poll invariant end to end.
//
// ReconcileOnce is SYSTEM-LEVEL (it sweeps every tenant), and the suite shares one migrated DB, so a test must
// assert on ITS OWN row's final state and ITS OWN tenant's alerts — never on the global sweep counts, which
// legitimately include other tests' rows.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// mockAlerter counts ContainmentFailed calls PER TENANT, so a test reads only its own tenant's alerts.
type mockAlerter struct {
	mu sync.Mutex
	m  map[uuid.UUID][2]int // tenant -> [failed, stalled]
}

func (a *mockAlerter) ContainmentFailed(ctx context.Context, tenantID, executionID uuid.UUID, actionKey, target, status string, stalled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[uuid.UUID][2]int{}
	}
	c := a.m[tenantID]
	if stalled {
		c[1]++
	} else {
		c[0]++
	}
	a.m[tenantID] = c
	return nil
}
func (a *mockAlerter) failed(tid uuid.UUID) int { a.mu.Lock(); defer a.mu.Unlock(); return a.m[tid][0] }
func (a *mockAlerter) stalled(tid uuid.UUID) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.m[tid][1]
}

// rowState reads a single execution row's status + confirmed flag (this tenant only).
func rowState(t *testing.T, db *database.DB, tid, runID uuid.UUID) (status string, confirmed bool) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, confirmed FROM soar_action_execution WHERE run_id=$1 AND step_index=0`, runID).
			Scan(&status, &confirmed)
	}); err != nil {
		t.Fatalf("rowState: %v", err)
	}
	return status, confirmed
}

func isoExecBackdated(t *testing.T, sup *soar.Supervisor, db *database.DB, tid uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("isolate: %s %v", st, err)
	}
	backdate(t, db, tid, runID, "10 minutes")
	return runID
}

func backdate(t *testing.T, db *database.DB, tid, runID uuid.UUID, interval string) {
	t.Helper()
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET claimed_at = now() - $2::interval WHERE run_id=$1`, runID, interval)
		return e
	}); err != nil {
		t.Fatalf("backdate: %v", err)
	}
}

// reconcileSetup builds the supervisor + a per-tenant alerter, enables destructive actions, and confirms this
// tenant's rows at cleanup (so a backdated leftover can't leak into a later test's sweep).
func reconcileSetup(t *testing.T) (*soar.Supervisor, *database.DB, uuid.UUID, *mdeMock, *mockAlerter) {
	t.Helper()
	sup, repo, db, tid, mock := setupDefender(t)
	_ = repo.SetSoarSettings(context.Background(), tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5})
	t.Cleanup(func() {
		_ = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET confirmed=true WHERE tenant_id=$1 AND NOT confirmed`, tid)
			return e
		})
	})
	al := &mockAlerter{}
	sup.WithAlerter(al)
	return sup, db, tid, mock, al
}

// Succeeded → the row is confirmed; no alert; the poll makes no isolate/unisolate POST.
func TestReconcile_SucceededConfirms(t *testing.T) {
	sup, db, tid, mock, al := reconcileSetup(t)
	runID := isoExecBackdated(t, sup, db, tid)
	mock.confirmStatus = "Succeeded"
	isoBefore, unisoBefore := atomic.LoadInt32(&mock.isolateCalls), atomic.LoadInt32(&mock.unisolCalls)

	if _, _, _, err := sup.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status, confirmed := rowState(t, db, tid, runID); !confirmed || status != "executed" {
		t.Fatalf("expected confirmed executed row, got status=%s confirmed=%v", status, confirmed)
	}
	if al.failed(tid) != 0 || al.stalled(tid) != 0 {
		t.Fatalf("no alert on success, got failed=%d stalled=%d", al.failed(tid), al.stalled(tid))
	}
	if atomic.LoadInt32(&mock.isolateCalls) != isoBefore || atomic.LoadInt32(&mock.unisolCalls) != unisoBefore {
		t.Fatal("reconcile poll must be READ-ONLY (no isolate/unisolate POST)")
	}
}

// Failed → the row flips to failed, alerts once, and is EXCLUDED from reverse (nothing to undo).
func TestReconcile_FailedAlertsAndExcludesReverse(t *testing.T) {
	sup, db, tid, mock, al := reconcileSetup(t)
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	runID := isoExecBackdated(t, sup, db, tid)
	mock.confirmStatus = "Failed"

	if _, _, _, err := sup.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status, _ := rowState(t, db, tid, runID); status != "failed" {
		t.Fatalf("failed containment must flip the row to failed, got %s", status)
	}
	if al.failed(tid) != 1 || al.stalled(tid) != 0 {
		t.Fatalf("failed containment must alert once (not stalled), got failed=%d stalled=%d", al.failed(tid), al.stalled(tid))
	}
	res, err := sup.ReverseRun(context.Background(), tid, actor, runID)
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	if n := atomic.LoadInt32(&mock.unisolCalls); n != 0 {
		t.Fatalf("failed containment must be excluded from reverse, got %d unisolate POSTs; res=%+v", n, res)
	}
}

// Non-terminal past the stall window → alerted (stalled), row left unchanged (may still succeed).
func TestReconcile_StalledAlerts(t *testing.T) {
	sup, db, tid, mock, al := reconcileSetup(t)
	runID := isoExecBackdated(t, sup, db, tid)
	backdate(t, db, tid, runID, "30 minutes") // past the 900s stall default
	mock.confirmStatus = "Pending"            // not terminal

	if _, _, _, err := sup.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status, confirmed := rowState(t, db, tid, runID); status != "executed" || confirmed {
		t.Fatalf("stalled row must stay executed/unconfirmed, got status=%s confirmed=%v", status, confirmed)
	}
	if al.stalled(tid) != 1 || al.failed(tid) != 0 {
		t.Fatalf("stalled action must alert as stalled, got stalled=%d failed=%d", al.stalled(tid), al.failed(tid))
	}
}

// G-1: a crash-resumed OWN isolate has a DISPLAY connector_ref but a bare prior_state.action_id; the reconciler
// polls action_id → confirms (no false 404/"unconfirmable").
func TestReconcile_G1CrashResumedConfirms(t *testing.T) {
	sup, db, tid, mock, al := reconcileSetup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("isolate: %s %v", st, err)
	}
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE soar_action_execution SET status='executing' WHERE run_id=$1 AND step_index=0`, runID)
		return e
	}); err != nil {
		t.Fatalf("crash: %v", err)
	}
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("resume: %s %v", st, err)
	}
	backdate(t, db, tid, runID, "10 minutes")
	mock.confirmStatus = "Succeeded"

	if _, _, _, err := sup.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, confirmed := rowState(t, db, tid, runID); !confirmed {
		t.Fatal("G-1: crash-resumed own action must confirm via action_id (not 404 on the display ref)")
	}
	if al.failed(tid) != 0 {
		t.Fatal("G-1: must not false-alert a confirmable own action")
	}
}

// G-2: a foreign isolation is never reconciled or alerted (changed=false → excluded from the poll list), even
// when the foreign action itself reports Failed.
func TestReconcile_G2ForeignNotReconciled(t *testing.T) {
	sup, db, tid, mock, al := reconcileSetup(t)
	ctx := context.Background()
	actor := auth.Principal{UserID: uuid.New(), Email: "a@t", TenantID: tid}
	mock.mu.Lock()
	mock.foreign = "Defender automated investigation isolate"
	mock.confirmStatus = "Failed"
	mock.mu.Unlock()
	runID := uuid.New()
	if st, _, err := sup.ExecuteConnectorStep(ctx, tid, actor, runID, 0, isoAct(), "host:WIN-EDR-3", nil); err != nil || st != soar.StatusExecuted {
		t.Fatalf("isolate no-op: %s %v", st, err)
	}
	backdate(t, db, tid, runID, "10 minutes")

	if _, _, _, err := sup.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if status, confirmed := rowState(t, db, tid, runID); status != "executed" || confirmed {
		t.Fatalf("G-2: foreign row must be untouched by the reconciler, got status=%s confirmed=%v", status, confirmed)
	}
	if al.failed(tid) != 0 || al.stalled(tid) != 0 {
		t.Fatalf("G-2: a foreign isolation's failure must NOT alert us, got failed=%d stalled=%d", al.failed(tid), al.stalled(tid))
	}
}
