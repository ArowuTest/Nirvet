package iam

// ADR-0007 refresh-token security suite (DB-gated). Proves rotation-on-use, theft/reuse detection (a replayed
// rotated token revokes the whole family), generation invalidation (a password change / offboard kills the
// chain), single-session logout, and rejection of an unknown token. Reuses resetSvc/seedUser from
// password_reset_test.go.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRefresh_RotationAndReuseDetection(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email}

	raw1, _, err := s.IssueRefresh(ctx, p)
	if err != nil || raw1 == "" {
		t.Fatalf("issue: err=%v", err)
	}

	// First redeem rotates: fresh access + a NEW refresh secret.
	access, raw2, ttl, err := s.RedeemRefresh(ctx, raw1)
	if err != nil || access == "" || raw2 == "" || ttl <= 0 {
		t.Fatalf("redeem: err=%v access?=%v raw2?=%v", err, access != "", raw2 != "")
	}
	if raw2 == raw1 {
		t.Fatal("rotation must produce a new secret")
	}

	// Replaying the ALREADY-ROTATED token = theft → error + whole family revoked.
	if _, _, _, err := s.RedeemRefresh(ctx, raw1); err == nil {
		t.Fatal("replay of a rotated token must be rejected (reuse detection)")
	}
	// ...and the successor is now dead too (family revoked).
	if _, _, _, err := s.RedeemRefresh(ctx, raw2); err == nil {
		t.Fatal("successor token must be revoked after a family reuse event")
	}
}

func TestRefresh_GenerationInvalidation(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT2, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT2, Email: email}

	raw, _, err := s.IssueRefresh(ctx, p)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// A password change / offboard bumps the user generation — every outstanding refresh must die.
	if err := s.BumpUserGeneration(ctx, tenantID, uid); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if _, _, _, err := s.RedeemRefresh(ctx, raw); err == nil {
		t.Fatal("refresh must be rejected after a user-generation bump")
	}
}

func TestRefresh_LogoutRevokes(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email}

	raw, _, err := s.IssueRefresh(ctx, p)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	s.RevokeRefreshToken(ctx, raw) // logout
	if _, _, _, err := s.RedeemRefresh(ctx, raw); err == nil {
		t.Fatal("a logged-out refresh token must not redeem")
	}
}

func TestRefresh_UnknownTokenRejected(t *testing.T) {
	s, _ := resetSvc(t)
	if _, _, _, err := s.RedeemRefresh(context.Background(), "not-a-real-token"); err == nil {
		t.Fatal("unknown refresh token must be rejected")
	}
}

func TestRefresh_DisabledUserCannotRefresh(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email}
	raw, _, err := s.IssueRefresh(ctx, p)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Disable the account (raw exec, avoiding coupling to a specific service method), then attempt refresh.
	if e := db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, ex := tx.Exec(ctx, `UPDATE users SET status=$1 WHERE id=$2`, string(UserDisabled), uid)
		return ex
	}); e != nil {
		t.Fatalf("disable: %v", e)
	}
	if _, _, _, err := s.RedeemRefresh(ctx, raw); err == nil {
		t.Fatal("a disabled user's refresh token must not redeem")
	}
}
