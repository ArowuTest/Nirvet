package platformadmin

// §6.18 #122 P-2 — the flag safety GATE: immutable rejected+audited, open no-reason, guarded needs-reason, protected
// weaken needs senior+four-eyes+reason+HIGH-alert, protected-toward-secure is guarded, rollback re-runs the gate.

import (
	"context"
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type mockPAAlerter struct{ n int }

func (m *mockPAAlerter) RaisePlatform(context.Context, uuid.UUID, string, string, string, string, string) (bool, error) {
	m.n++
	return true, nil
}

func padminActor() auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: uuid.New(), Role: auth.RolePlatformAdmin, Email: "padmin@nirvet"}
}

func status(err error) int {
	if ae, ok := err.(*httpx.APIError); ok {
		return ae.Status
	}
	return 0
}

func lastAuditReason(t *testing.T, db *database.DB, key string) string {
	t.Helper()
	var reason string
	_ = db.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT reason FROM platform_config_audit WHERE key=$1 ORDER BY created_at DESC LIMIT 1`, key).Scan(&reason)
	})
	return reason
}

func TestGate_ImmutableRejectedAndAudited(t *testing.T) {
	db := paDB(t)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	_, err := svc.SetFlag(context.Background(), padminActor(), SetFlagInput{Key: TestFlagImmutable, Enabled: false, Reason: "x"})
	if status(err) != 400 {
		t.Fatalf("immutable flag must be rejected 400, got %v", err)
	}
	if !strings.HasPrefix(lastAuditReason(t, db, TestFlagImmutable), "REJECTED:") {
		t.Fatal("the rejected attempt must be audited")
	}
}

func TestGate_OpenNoReason(t *testing.T) {
	db := paDB(t)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	res, err := svc.SetFlag(context.Background(), padminActor(), SetFlagInput{Key: TestFlagOpen, Enabled: true})
	if err != nil || !res.Applied {
		t.Fatalf("open flag should apply without a reason: %v", err)
	}
}

func TestGate_GuardedNeedsReason(t *testing.T) {
	db := paDB(t)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	a := padminActor()
	if _, err := svc.SetFlag(context.Background(), a, SetFlagInput{Key: TestFlagGuarded, Enabled: true}); status(err) != 400 {
		t.Fatalf("guarded flag must require a reason, got %v", err)
	}
	if _, err := svc.SetFlag(context.Background(), a, SetFlagInput{Key: TestFlagGuarded, Enabled: true, Reason: "enable for pilot"}); err != nil {
		t.Fatalf("guarded flag with a reason should apply: %v", err)
	}
}

func TestGate_ProtectedWeakenNeedsFourEyes(t *testing.T) {
	db := paDB(t)
	al := &mockPAAlerter{}
	svc := NewService(NewRepository(db), al)
	a := padminActor()
	ctx := context.Background()

	// The protected fixture is secure=ON; setting it OFF is a weakening. No approver → four-eyes 403.
	_, err := svc.SetFlag(ctx, a, SetFlagInput{Key: TestFlagProtected, Enabled: false, Reason: "temp"})
	if status(err) != 403 {
		t.Fatalf("weakening a protected flag without a distinct approver must be 403, got %v", err)
	}
	// Same-user "approver" is not four-eyes.
	if _, err := svc.SetFlag(ctx, a, SetFlagInput{Key: TestFlagProtected, Enabled: false, Reason: "temp", ApprovedBy: &a.UserID}); status(err) != 403 {
		t.Fatalf("self-approval is not four-eyes, want 403, got %v", err)
	}
	// Distinct approver + reason → applied, weakening delta, HIGH alert raised.
	approver := uuid.New()
	res, err := svc.SetFlag(ctx, a, SetFlagInput{Key: TestFlagProtected, Enabled: false, Reason: "incident triage", ApprovedBy: &approver})
	if err != nil || !res.Applied || !res.LessSecure {
		t.Fatalf("weaken with four-eyes should apply: res=%+v err=%v", res, err)
	}
	if !strings.Contains(res.SecurityDelta, "LESS-SECURE") {
		t.Fatalf("delta must surface the weakening: %q", res.SecurityDelta)
	}
	if al.n != 1 {
		t.Fatalf("weakening a protected flag must raise exactly one HIGH alert, got %d", al.n)
	}
}

func TestGate_ProtectedTowardSecureIsGuarded(t *testing.T) {
	db := paDB(t)
	svc := NewService(NewRepository(db), &mockPAAlerter{})
	a := padminActor()
	// Enabling the protected fixture (its secure state) is toward-secure → guarded (reason, no four-eyes).
	if _, err := svc.SetFlag(context.Background(), a, SetFlagInput{Key: TestFlagProtected, Enabled: true, Reason: "restore"}); err != nil {
		t.Fatalf("tightening a protected flag should apply with just a reason: %v", err)
	}
}

func TestGate_RollbackReRunsGate(t *testing.T) {
	db := paDB(t)
	repo := NewRepository(db)
	svc := NewService(repo, &mockPAAlerter{})
	a := padminActor()
	ctx := context.Background()

	// Weaken (with four-eyes) → this creates an audit row whose value is the LESS-secure state.
	approver := uuid.New()
	if _, err := svc.SetFlag(ctx, a, SetFlagInput{Key: TestFlagProtected, Scope: "global", Enabled: false, Reason: "triage", ApprovedBy: &approver}); err != nil {
		t.Fatalf("weaken: %v", err)
	}
	var weakenAuditID uuid.UUID
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM platform_config_audit WHERE key=$1 AND new_value->>'enabled'='false' ORDER BY created_at DESC LIMIT 1`, TestFlagProtected).Scan(&weakenAuditID)
	}); err != nil {
		t.Fatalf("find audit: %v", err)
	}
	// Restore to secure.
	if _, err := svc.SetFlag(ctx, a, SetFlagInput{Key: TestFlagProtected, Scope: "global", Enabled: true, Reason: "restore"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// Rolling BACK to the weakened value re-runs the gate → needs the four-eyes envelope; without it, 403.
	if _, err := svc.RollbackFlag(ctx, a, weakenAuditID, nil); status(err) != 403 {
		t.Fatalf("rollback into a less-secure state must re-run the gate (403 without four-eyes), got %v", err)
	}
}
