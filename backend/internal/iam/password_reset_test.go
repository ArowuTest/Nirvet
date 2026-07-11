package iam

// G1 admin-issued password reset — adversarial suite. Proves: issue→confirm sets the password AND revokes the
// user's live sessions (RP-5); token is single-use and expiry-bound; the RP-1 role-domain boundary (customer_admin
// can't reset a provider user); RP-6 (SSO-only refused at issue, disabled refused at CONFIRM time); and an invalid
// token is a generic rejection (no enumeration).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func resetSvc(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	tokens := auth.NewManager("reset-test-secret-0123456789", "nirvet", time.Hour)
	return NewService(NewRepository(db), db, tokens, cipher), db // no resetBaseURL → returnLink yields the raw token
}

func seedUser(t *testing.T, db *database.DB, tenantID uuid.UUID, role auth.Role, password string, status UserStatus) (uuid.UUID, string) {
	t.Helper()
	uid := uuid.New()
	email := "u-" + uid.String() + "@x"
	var hash string
	if password != "" {
		hash, _ = auth.HashPassword(password)
	}
	if err := db.WithTenant(context.Background(), tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, password_hash, role, status) VALUES ($1,$2,$3,$4,$5,$6)`,
			uid, tenantID, email, hash, string(role), string(status))
		return e
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return uid, email
}

func padminOf(tenantID uuid.UUID) auth.Principal {
	return auth.Principal{UserID: uuid.New(), TenantID: tenantID, Role: auth.RolePlatformAdmin, Email: "admin@x"}
}

func TestReset_IssueConfirmRevokesAndRotates(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "oldpassword", UserActive)
	sess := mintPrincipal(t, s, auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email})

	res, token, err := s.IssuePasswordReset(ctx, padminOf(tenantID), tenantID, uid, true)
	if err != nil || res.UserID != uid || token == "" {
		t.Fatalf("issue: err=%v token=%q", err, token)
	}
	if err := s.ConfirmPasswordReset(ctx, token, "newpassword123"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// RP-5: the user's pre-reset session is revoked.
	if status(s.CheckSession(ctx, sess, "")) != 401 {
		t.Fatal("a reset must revoke the user's existing sessions")
	}
	// New password logs in; old one does not.
	if _, err := s.Login(ctx, email, "newpassword123", "", "req"); err != nil {
		t.Fatalf("new password must log in: %v", err)
	}
	if _, err := s.Login(ctx, email, "oldpassword", "", "req"); err == nil {
		t.Fatal("old password must no longer log in")
	}
}

func TestReset_TokenSingleUse(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, _ := seedUser(t, db, tenantID, auth.RoleAnalystT1, "oldpassword", UserActive)
	_, token, _ := s.IssuePasswordReset(ctx, padminOf(tenantID), tenantID, uid, true)
	if err := s.ConfirmPasswordReset(ctx, token, "newpassword123"); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	if err := s.ConfirmPasswordReset(ctx, token, "another12345"); err == nil {
		t.Fatal("a reset token must be single-use")
	}
}

func TestReset_Expired(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, _ := seedUser(t, db, tenantID, auth.RoleAnalystT1, "oldpassword", UserActive)
	_, token, _ := s.IssuePasswordReset(ctx, padminOf(tenantID), tenantID, uid, true)
	_ = db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE password_reset_tokens SET expires_at = now() - interval '1 hour' WHERE user_id=$1`, uid)
		return e
	})
	if err := s.ConfirmPasswordReset(ctx, token, "newpassword123"); err == nil {
		t.Fatal("an expired reset token must be rejected")
	}
}

func TestReset_RoleDomainGuard(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, _ := seedUser(t, db, tenantID, auth.RoleAnalystT1, "oldpassword", UserActive) // a PROVIDER-role user
	custAdmin := auth.Principal{UserID: uuid.New(), TenantID: tenantID, Role: auth.RoleCustomerAdmin, Email: "ca@x"}
	if _, _, err := s.IssuePasswordReset(ctx, custAdmin, tenantID, uid, true); err == nil {
		t.Fatal("RP-1: a customer_admin must not reset a provider-role user")
	}
}

func TestReset_SSOUserRefusedAtIssue(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, _ := seedUser(t, db, tenantID, auth.RoleCustomerViewer, "", UserActive) // no local password (SSO-only)
	if _, _, err := s.IssuePasswordReset(ctx, padminOf(tenantID), tenantID, uid, true); err == nil {
		t.Fatal("RP-6: an SSO-only user (no local password) must not be resettable")
	}
}

func TestReset_DisabledRefusedAtConfirm(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, _ := seedUser(t, db, tenantID, auth.RoleAnalystT1, "oldpassword", UserActive)
	_, token, _ := s.IssuePasswordReset(ctx, padminOf(tenantID), tenantID, uid, true)
	// Disable the account AFTER the token was issued.
	_ = db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, uid)
		return e
	})
	if err := s.ConfirmPasswordReset(ctx, token, "newpassword123"); err == nil {
		t.Fatal("RP-6: a reset must be refused at confirm time for a disabled account (never re-enable it)")
	}
}

// TestLogin_FailedAttemptIsAudited (M5) proves a bad-password login against a KNOWN account writes an
// immutable auth.login_failed row in that tenant's audit trail — so a spray against a real account is
// reconstructable post-incident, not just a mutable counter that resets on the next success.
func TestLogin_FailedAttemptIsAudited(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	_, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "correcthorse", UserActive)

	if _, err := s.Login(ctx, email, "wrongpassword", "", "req-1"); err == nil {
		t.Fatal("a wrong password must be rejected")
	}
	var n int
	if err := db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='auth.login_failed'`).Scan(&n)
	}); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 auth.login_failed audit row, got %d", n)
	}
}

func TestReset_InvalidTokenRejected(t *testing.T) {
	s, _ := resetSvc(t)
	if err := s.ConfirmPasswordReset(context.Background(), "nvr_deadbeefdeadbeef", "newpassword123"); err == nil {
		t.Fatal("an invalid reset token must be rejected")
	}
	if err := s.ConfirmPasswordReset(context.Background(), "not-a-reset-token", "newpassword123"); err == nil {
		t.Fatal("a token without the nvr_ scheme must be rejected")
	}
}
