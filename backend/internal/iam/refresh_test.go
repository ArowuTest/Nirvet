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

func TestRefresh_AbsoluteFamilyCap(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email}

	raw, _, err := s.IssueRefresh(ctx, p)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Age the family PAST the absolute cap (but leave the sliding expiry in the future) — the token would still
	// pass the per-row expiry check, so only the absolute cap can reject it.
	if e := db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, ex := tx.Exec(ctx, `UPDATE refresh_tokens SET family_started_at = now() - ($1::interval + interval '1 day') WHERE user_id=$2`,
			absoluteRefreshFamilyTTL, uid)
		return ex
	}); e != nil {
		t.Fatalf("age family: %v", e)
	}
	if _, _, _, err := s.RedeemRefresh(ctx, raw); err == nil {
		t.Fatal("a refresh past the absolute family cap must be rejected")
	}
}

func TestRefresh_LogoutAllRevokesEveryFamily(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email}

	// Two independent login families (e.g. two devices).
	raw1, _, err := s.IssueRefresh(ctx, p)
	if err != nil {
		t.Fatalf("issue1: %v", err)
	}
	raw2, _, err := s.IssueRefresh(ctx, p)
	if err != nil {
		t.Fatalf("issue2: %v", err)
	}
	if err := s.RevokeAllUserRefreshTokens(ctx, tenantID, uid); err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if _, _, _, err := s.RedeemRefresh(ctx, raw1); err == nil {
		t.Fatal("family 1 must be dead after logout-all")
	}
	if _, _, _, err := s.RedeemRefresh(ctx, raw2); err == nil {
		t.Fatal("family 2 must be dead after logout-all")
	}
}

func TestRefresh_ReaperPurgesDeadRows(t *testing.T) {
	s, db := resetSvc(t)
	ctx := context.Background()
	tenantID := uuid.New()
	uid, email := seedUser(t, db, tenantID, auth.RoleAnalystT1, "pw12345678", UserActive)
	p := auth.Principal{UserID: uid, TenantID: tenantID, Role: auth.RoleAnalystT1, Email: email}

	if _, _, err := s.IssueRefresh(ctx, p); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Expire the row so the reaper considers it dead.
	if e := db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, ex := tx.Exec(ctx, `UPDATE refresh_tokens SET expires_at = now() - interval '1 hour' WHERE user_id=$1`, uid)
		return ex
	}); e != nil {
		t.Fatalf("expire: %v", e)
	}
	n, err := s.PurgeDeadRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least one dead row purged, got %d", n)
	}
	// A live (freshly-issued) row must survive a subsequent sweep.
	if _, _, err := s.IssueRefresh(ctx, p); err != nil {
		t.Fatalf("issue2: %v", err)
	}
	if n2, err := s.PurgeDeadRefreshTokens(ctx); err != nil {
		t.Fatalf("purge2: %v", err)
	} else if n2 != 0 {
		t.Fatalf("live row must NOT be purged, got %d deleted", n2)
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
