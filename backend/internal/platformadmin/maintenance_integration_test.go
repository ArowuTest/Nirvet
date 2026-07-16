package platformadmin

// §6.18 #122 P-4 — maintenance windows (M-2: critical breaks through) + protected time-box auto-revert (Reinf-B).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestMaintenance_CriticalBreaksThrough(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	repo := NewRepository(db)
	m := NewMaintenanceService(repo)
	ctx := context.Background()

	// A TENANT-scoped window suppressing notifications + pausing SLA, active now (tenant-scoped so it doesn't leak
	// into other tests via the global scope).
	if err := m.CreateWindow(ctx, padminActor(), "tenant", tid.String(), time.Now().Add(-time.Minute), time.Now().Add(time.Hour), true, true, "planned maintenance"); err != nil {
		t.Fatalf("create window: %v", err)
	}
	if !m.SuppressNotification(ctx, tid, "medium") {
		t.Fatal("a medium notification should be suppressed during a window")
	}
	if m.SuppressNotification(ctx, tid, "critical") {
		t.Fatal("M-2: a CRITICAL notification must break through suppression")
	}
	if m.PauseSLA(ctx, tid, "critical") {
		t.Fatal("SLA must never be paused for a critical incident")
	}
	if !m.PauseSLA(ctx, tid, "medium") {
		t.Fatal("a medium SLA may be paused during a window")
	}
}

func TestMaintenance_NoWindowNoSuppression(t *testing.T) {
	db := paDB(t)
	tid := paTenant(t, db)
	m := NewMaintenanceService(NewRepository(db))
	if m.SuppressNotification(context.Background(), tid, "medium") {
		t.Fatal("no active window → nothing suppressed")
	}
}

// Reinf-B: a weakened protected flag whose time-box elapsed is auto-reverted to its secure default by the sweep.
func TestReinfB_TimeBoxAutoRevert(t *testing.T) {
	db := paDB(t)
	repo := NewRepository(db)
	al := &mockPAAlerter{}
	svc := NewService(repo, al)
	a := padminActor()
	ctx := context.Background()

	// platform_feature_flags is package-shared state; start from a known baseline so a global row left by another
	// test cannot decide this one's outcome.
	clearFlag(t, db, TestFlagProtected)

	// Weaken the protected fixture (secure=ON) → OFF, with four-eyes. It gets a default time-box.
	approver := uuid.New()
	if _, err := svc.SetFlag(ctx, a, SetFlagInput{Key: TestFlagProtected, Scope: "global", Enabled: false, Reason: "triage", ApprovedBy: &approver}); err != nil {
		t.Fatalf("weaken: %v", err)
	}
	if NewFlagResolver(db).Enabled(ctx, uuid.New(), TestFlagProtected) {
		t.Fatal("precondition: the flag should be weakened (off) before expiry")
	}
	// Age the time-box into the past.
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE platform_feature_flags SET expires_at = now() - interval '1 minute'
			WHERE key=$1 AND scope='global'`, TestFlagProtected)
		return e
	}); err != nil {
		t.Fatalf("age expiry: %v", err)
	}
	n, err := svc.RevertExpiredWeakenings(ctx, 100)
	if err != nil || n < 1 {
		t.Fatalf("sweep should revert the expired weakening: n=%d err=%v", n, err)
	}
	if !NewFlagResolver(db).Enabled(ctx, uuid.New(), TestFlagProtected) {
		t.Fatal("Reinf-B: an expired protected weakening must auto-revert to its secure default (ON)")
	}
	if al.n < 1 {
		t.Fatal("auto-revert must raise a HIGH alert")
	}
}
