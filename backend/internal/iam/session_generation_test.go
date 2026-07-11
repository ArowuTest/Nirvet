package iam

// Session revocation — the heavy adversarial suite. Proves: a token is valid until its generation is bumped then
// REVOKED; a tenant bump kills EVERY session in the tenant but not another tenant's; the tombstone SURVIVES the
// offboard purge (revoked-stays-revoked even after the tenant's data is gone); API-key/service-account principals
// are exempt; in-flight (gen 0) tokens are valid until the first bump; and a resolution failure fails CLOSED as a
// TRANSIENT 503, not a session-killing 401.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/ArowuTest/nirvet/internal/platform/testsupport"
	"github.com/ArowuTest/nirvet/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func genDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func genSvc(t *testing.T, db *database.DB) *Service {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cipher, _ := crypto.NewLocal(base64.StdEncoding.EncodeToString(key), nil)
	tokens := auth.NewManager("test-session-secret-0123456789", "nirvet", time.Hour)
	return NewService(NewRepository(db), db, tokens, cipher)
}

// mintPrincipal mints a token for p through the chokepoint and returns the verified principal (with gen/tgen
// stamped) — i.e. exactly what a request would carry.
func mintPrincipal(t *testing.T, s *Service, p auth.Principal) auth.Principal {
	t.Helper()
	tok, err := s.MintSession(context.Background(), &p, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := s.tokens.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return got
}

func principal(tenant, user uuid.UUID) auth.Principal {
	return auth.Principal{UserID: user, TenantID: tenant, Role: auth.RoleAnalystT1, Email: "a@x"}
}

func status(err error) int {
	var ae *httpx.APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// Valid until the user's generation is bumped, then revoked (401).
func TestSessionGen_UserBumpRevokes(t *testing.T) {
	s := genSvc(t, genDB(t))
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	p := mintPrincipal(t, s, principal(tenant, user))

	if err := s.CheckSession(ctx, p, ""); err != nil {
		t.Fatalf("fresh session must be valid: %v", err)
	}
	if err := s.BumpUserGeneration(ctx, tenant, user); err != nil {
		t.Fatalf("bump: %v", err)
	}
	err := s.CheckSession(ctx, p, "")
	if status(err) != 401 {
		t.Fatalf("after a user-gen bump the old token must be revoked (401), got %v", err)
	}
	// A NEWLY minted token (stamped at the new generation) is valid again.
	if err := s.CheckSession(ctx, mintPrincipal(t, s, principal(tenant, user)), ""); err != nil {
		t.Fatalf("a token minted after the bump must be valid: %v", err)
	}
}

// A tenant bump kills EVERY session in the tenant; another tenant's session is untouched.
func TestSessionGen_TenantBumpKillsAllButNotOthers(t *testing.T) {
	s := genSvc(t, genDB(t))
	ctx := context.Background()
	tenant, other := uuid.New(), uuid.New()
	pA := mintPrincipal(t, s, principal(tenant, uuid.New()))
	pB := mintPrincipal(t, s, principal(tenant, uuid.New()))
	pOther := mintPrincipal(t, s, principal(other, uuid.New()))

	if err := s.BumpTenantGeneration(ctx, tenant); err != nil {
		t.Fatalf("tenant bump: %v", err)
	}
	if status(s.CheckSession(ctx, pA, "")) != 401 || status(s.CheckSession(ctx, pB, "")) != 401 {
		t.Fatal("a tenant bump must revoke every session in the tenant")
	}
	if err := s.CheckSession(ctx, pOther, ""); err != nil {
		t.Fatalf("another tenant's session must be untouched: %v", err)
	}
}

// THE key property: the generation tombstone SURVIVES the offboard purge — a revoked token stays revoked even
// after the tenant's data is purged. Bump (cache-bust, no read) → purge → the first read is from the DB, so this
// genuinely proves the row survived rather than a cached value masking a deleted row.
func TestSessionGen_TombstoneSurvivesOffboardPurge(t *testing.T) {
	db := genDB(t)
	s := genSvc(t, db)
	ctx := context.Background()
	// A real tenant, moved to the 'exported' state with an elapsed retention window so the (fully-guarded) purge
	// proceeds — exercising the ACTUAL purge, not a guard-stripped one.
	tn, err := tenant.NewService(tenant.NewRepository(db)).Create(ctx, tenant.CreateInput{Name: "offb-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenantID, user := tn.ID, uuid.New()
	p := mintPrincipal(t, s, principal(tenantID, user)) // tgen 0

	if err := s.BumpTenantGeneration(ctx, tenantID); err != nil { // tgen -> 1, cache-busted
		t.Fatalf("tenant bump: %v", err)
	}
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE tenants SET status='exported', exported_at=now()-interval '1 day',
		                        offboard_retention_days=0, legal_hold=false WHERE id=$1`, tenantID)
		return e
	}); err != nil {
		t.Fatalf("set exported state: %v", err)
	}
	// Run the real offboard purge (SECURITY DEFINER, full guard chain) for this tenant.
	if err := db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `SELECT tenant_offboard_purge($1)`, tenantID)
		return e
	}); err != nil {
		t.Fatalf("purge: %v", err)
	}
	// The pre-offboard token must STILL be revoked — the tenant_session_state tombstone (gen 1) survived the purge.
	if status(s.CheckSession(ctx, p, "")) != 401 {
		t.Fatal("tombstone must survive the purge: an offboarded tenant's token must stay revoked (401)")
	}
}

// Service-account (API key) principals are exempt — their lifecycle is key deletion, so a generation bump must not
// break telemetry/ingest.
func TestSessionGen_ServiceAccountExempt(t *testing.T) {
	s := genSvc(t, genDB(t))
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	if err := s.BumpUserGeneration(ctx, tenant, user); err != nil {
		t.Fatalf("bump: %v", err)
	}
	p := principal(tenant, user)
	p.ServiceAccount = true // gen 0, behind current — but exempt
	if err := s.CheckSession(ctx, p, ""); err != nil {
		t.Fatalf("a service-account principal must be exempt from the generation check: %v", err)
	}
}

// An in-flight token minted before the feature (gen 0) is valid while the generation is still 0, then honours the
// first bump.
func TestSessionGen_InFlightTokenValidUntilFirstBump(t *testing.T) {
	s := genSvc(t, genDB(t))
	ctx := context.Background()
	tenant, user := uuid.New(), uuid.New()
	p := principal(tenant, user) // Gen/TGen default 0, as a pre-feature token would carry
	if err := s.CheckSession(ctx, p, ""); err != nil {
		t.Fatalf("a gen-0 token must be valid before any bump: %v", err)
	}
	if err := s.BumpUserGeneration(ctx, tenant, user); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if status(s.CheckSession(ctx, p, "")) != 401 {
		t.Fatal("after the first bump, the gen-0 in-flight token must be revoked")
	}
}

// SR-4: a resolution failure fails CLOSED but TRANSIENT — 503 (retryable), not a session-killing 401. Forced with
// a closed DB connection so the cache-miss read errors.
func TestSessionGen_FailClosedTransient503(t *testing.T) {
	deadDB, err := database.Connect(context.Background(), testsupport.RequireDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	deadDB.Close() // subsequent queries error
	s := genSvc(t, deadDB)
	// A fresh tenant/user → cache miss → the DB read errors on the dead pool.
	p := principal(uuid.New(), uuid.New())
	err = s.CheckSession(context.Background(), p, "")
	if status(err) != 503 {
		t.Fatalf("a resolution failure must deny as a TRANSIENT 503, not a 401; got %v (status %d)", err, status(err))
	}
	if strings.Contains(strings.ToLower(err.Error()), "revoked") {
		t.Fatal("the transient failure must not masquerade as a hard revocation")
	}
}
