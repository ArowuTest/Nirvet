package soar_test

// D5 arm-gate: destructive response must refuse to arm for a tenant that has not DECIDED about its crown jewels.
//
// The first test here is the one that matters, and it is a mutation check on a mistake I actually made while
// writing this: my first cut counted protected_directory_roles WITHOUT excluding globals. 0066 seeds four
// privileged Entra roles as global rows that every tenant can read, so every tenant would have counted >= 4
// designations from birth, Decided would always have been true, and the gate would never have blocked a single
// arm. It would have passed review as "the gate exists" while being incapable of firing — a safety check that
// cannot fail, which is worse than no check because it reads like one.
//
// So: TestArmGate_FreshTenantRefused is not a formality. Revert the `WHERE tenant_id IS NOT NULL` in
// countProtectedTargets and it goes red. That is the only reason to trust the rest.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/soar"
	"github.com/ArowuTest/nirvet/internal/tenant"
)

func setupArmGate(t *testing.T) (*soar.Service, *soar.Repository, uuid.UUID, auth.Principal) {
	t.Helper()
	dsn := testsupport.RequireDSN(t)
	db, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	repo := soar.NewRepository(db)
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(context.Background(), tenant.CreateInput{Name: "armgate-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return soar.NewService(repo), repo, tn.ID, auth.Principal{UserID: uuid.New(), Email: "padmin@op", TenantID: tn.ID}
}

// armErrCode returns the APIError code, or "" for any other error.
func armErrCode(err error) string {
	var ae *httpx.APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func armOn() soar.SoarSettings {
	return soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 5}
}

// THE test. A brand-new tenant has designated nothing and attested nothing → arming must be refused, even though
// it inherits 0066's four global directory roles.
func TestArmGate_FreshTenantRefused(t *testing.T) {
	svc, _, tid, p := setupArmGate(t)

	dec, err := svc.ProtectedDecision(context.Background(), tid)
	if err != nil {
		t.Fatalf("decision: %v", err)
	}
	if dec.TargetCount != 0 {
		t.Fatalf("fresh tenant has TargetCount=%d, want 0 — inherited globals must NOT count as this tenant's "+
			"decision, or the gate can never fire", dec.TargetCount)
	}
	if dec.Decided {
		t.Fatal("fresh tenant reports Decided=true — the gate would never block an arm")
	}

	_, err = svc.SetSettings(context.Background(), p, tid, armOn())
	if code := armErrCode(err); code != soar.CodeProtectedTargetsUndecided {
		t.Fatalf("arming an undecided tenant: err=%v code=%q; want %q", err, code, soar.CodeProtectedTargetsUndecided)
	}
}

// Designating a crown jewel is a decision → arming is allowed.
func TestArmGate_DesignatedTargetUnblocks(t *testing.T) {
	svc, _, tid, p := setupArmGate(t)
	if _, err := svc.AddProtectedTarget(context.Background(), p, soar.ProtectedKindHost, "dc01", "domain controller"); err != nil {
		t.Fatalf("designate: %v", err)
	}
	if _, err := svc.SetSettings(context.Background(), p, tid, armOn()); err != nil {
		t.Fatalf("arming after designating a target: %v", err)
	}
}

// Attesting "this tenant designates none" is equally a decision → arming is allowed. This is the branch that
// keeps the gate from being a "just add a dummy row" ritual.
func TestArmGate_AckUnblocks(t *testing.T) {
	svc, _, tid, p := setupArmGate(t)
	if _, err := svc.AckProtectedTargets(context.Background(), p, "K. Mensah, IT Director", "no crown jewels in scope for phase 1"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	dec, _ := svc.ProtectedDecision(context.Background(), tid)
	if !dec.Decided || dec.Ack == nil {
		t.Fatalf("after ack: Decided=%v Ack=%v; want decided with an ack", dec.Decided, dec.Ack)
	}
	if dec.Ack.ConfirmedWith != "K. Mensah, IT Director" {
		t.Errorf("ConfirmedWith = %q; the attestation must record who at the customer confirmed", dec.Ack.ConfirmedWith)
	}
	if _, err := svc.SetSettings(context.Background(), p, tid, armOn()); err != nil {
		t.Fatalf("arming after attestation: %v", err)
	}
}

// An attestation with nobody's name on it is the silent default wearing a hat.
func TestArmGate_AckRequiresAName(t *testing.T) {
	svc, _, _, p := setupArmGate(t)
	for _, cw := range []string{"", "  ", "ok"} {
		if _, err := svc.AckProtectedTargets(context.Background(), p, cw, ""); err == nil {
			t.Errorf("ack accepted confirmed_with=%q — the SOC cannot attest on the customer's behalf anonymously", cw)
		}
	}
}

// DISARMING must never be blocked. A safety gate that can trap a tenant in the armed state is a worse hazard than
// the one it guards against.
func TestArmGate_DisableNeverBlocked(t *testing.T) {
	svc, _, tid, p := setupArmGate(t)
	if _, err := svc.SetSettings(context.Background(), p, tid, soar.SoarSettings{DestructiveEnabled: false, MaxClass3PerHour: 5}); err != nil {
		t.Fatalf("disabling an undecided tenant must be allowed, got: %v", err)
	}
}

// The gate fires on the TRANSITION, not on every write: an already-armed tenant must be able to re-save its rate
// limits without being refused. (Reachable only via the repo, which is how a tenant armed before this gate
// existed — the pre-existing-state case.)
func TestArmGate_AlreadyArmedCanUpdate(t *testing.T) {
	svc, repo, tid, p := setupArmGate(t)
	if err := repo.SetSoarSettings(context.Background(), tid, armOn()); err != nil {
		t.Fatalf("pre-arm via repo: %v", err)
	}
	if _, err := svc.SetSettings(context.Background(), p, tid, soar.SoarSettings{DestructiveEnabled: true, MaxClass3PerHour: 9}); err != nil {
		t.Fatalf("re-saving an already-armed tenant must not be refused, got: %v", err)
	}
}

// Withdrawing the attestation re-blocks a FUTURE arm.
func TestArmGate_WithdrawnAckReblocks(t *testing.T) {
	svc, _, tid, p := setupArmGate(t)
	if _, err := svc.AckProtectedTargets(context.Background(), p, "K. Mensah, IT Director", ""); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := svc.WithdrawProtectedTargetsAck(context.Background(), p); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	dec, _ := svc.ProtectedDecision(context.Background(), tid)
	if dec.Decided {
		t.Fatal("withdrawn attestation still reports Decided=true")
	}
	_, err := svc.SetSettings(context.Background(), p, tid, armOn())
	if code := armErrCode(err); code != soar.CodeProtectedTargetsUndecided {
		t.Fatalf("arming after withdrawal: code=%q; want %q", code, soar.CodeProtectedTargetsUndecided)
	}
}
