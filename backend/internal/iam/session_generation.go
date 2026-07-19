package iam

// Session revocation via a monotonic session GENERATION (§6.2, HEAVY). A token is stamped at mint with the
// current per-user (gen) and per-tenant (tgen) generation; the per-request CheckSession rejects a token whose
// generation is behind current. Bumping a generation immediately invalidates every older token — the mechanism
// that kills a live stateless-JWT session on password change/reset, tenant offboard, or (future) admin-disable.
//
// Latency SLA (seeded config, tunable) — state it PRECISELY for an auditor: a bump is IMMEDIATE on the node that
// handles it (it cache-busts its own entry); in a MULTI-NODE deployment other nodes keep serving the cached
// generation until their TTL expires, so cross-node revocation is within cache_ttl_seconds (default 30s). The
// Ghana sovereign deployment is SINGLE-NODE, so revocation is effectively immediate. The cache is process-local
// (sync.Map); TRUE cross-node immediacy is a scale-out item (cross-node cache invalidation via LISTEN/NOTIFY or
// pub/sub) — but the TTL bound already guarantees revocation everywhere within the SLA, so this is a latency
// caveat, not a correctness hole. Fail direction (SR-4): if the current
// generation can't be resolved (cache miss + DB error), the check DENIES — but as a TRANSIENT 503 (retryable),
// not a session-killing 401, so a genuinely-revoked token stays blocked during the blip while a legitimate one
// retries and succeeds on recovery. A warm cache never triggers this.

import (
	"context"
	"sync"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type cachedGen struct {
	gen     int64
	expires time.Time
}

var (
	userGenCache   sync.Map // "tenant:user" -> cachedGen
	tenantGenCache sync.Map // tenantID -> cachedGen

	genTTLMu      sync.Mutex
	genTTL        time.Duration
	genTTLExpires time.Time
)

const defaultGenTTL = 30 * time.Second

// genCacheTTL returns the seeded revocation-latency SLA (session_revocation_config.cache_ttl_seconds), refreshed
// at most once a minute so a sovereign's runtime change is picked up without a restart.
func (s *Service) genCacheTTL(ctx context.Context) time.Duration {
	genTTLMu.Lock()
	defer genTTLMu.Unlock()
	if genTTL > 0 && time.Now().Before(genTTLExpires) {
		return genTTL
	}
	secs := 0
	_ = s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT cache_ttl_seconds FROM session_revocation_config WHERE scope='global'`).Scan(&secs)
	})
	if secs <= 0 {
		genTTL = defaultGenTTL
	} else {
		genTTL = time.Duration(secs) * time.Second
	}
	genTTLExpires = time.Now().Add(time.Minute)
	return genTTL
}

// currentUserGen returns the user's current generation (cache-first). An absent row is generation 0. On a cache
// miss + DB error it returns the error → the caller fails CLOSED (503).
func (s *Service) currentUserGen(ctx context.Context, tenantID, userID uuid.UUID) (int64, error) {
	key := tenantID.String() + ":" + userID.String()
	if c, ok := userGenCache.Load(key); ok {
		if cg := c.(cachedGen); time.Now().Before(cg.expires) {
			return cg.gen, nil
		}
	}
	var gen int64
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT generation FROM user_session_state WHERE user_id=$1`, userID).Scan(&gen)
		if e == pgx.ErrNoRows {
			gen = 0
			return nil
		}
		return e
	})
	if err != nil {
		return 0, err
	}
	userGenCache.Store(key, cachedGen{gen: gen, expires: time.Now().Add(s.genCacheTTL(ctx))})
	return gen, nil
}

// currentTenantGen returns the tenant's current generation (cache-first). Absent = 0. Errors fail closed.
func (s *Service) currentTenantGen(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	if c, ok := tenantGenCache.Load(tenantID); ok {
		if cg := c.(cachedGen); time.Now().Before(cg.expires) {
			return cg.gen, nil
		}
	}
	var gen int64
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT generation FROM tenant_session_state WHERE tenant_id=$1`, tenantID).Scan(&gen)
		if e == pgx.ErrNoRows {
			gen = 0
			return nil
		}
		return e
	})
	if err != nil {
		return 0, err
	}
	tenantGenCache.Store(tenantID, cachedGen{gen: gen, expires: time.Now().Add(s.genCacheTTL(ctx))})
	return gen, nil
}

// BumpUserGeneration increments a user's generation (immediate revocation of all their older tokens) and
// cache-busts the entry so the effect is immediate on this node. Triggers: password change/reset, admin-disable.
func (s *Service) BumpUserGeneration(ctx context.Context, tenantID, userID uuid.UUID) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO user_session_state (tenant_id, user_id, generation) VALUES ($1,$2,1)
			 ON CONFLICT (tenant_id, user_id) DO UPDATE SET generation = user_session_state.generation + 1, updated_at=now()`,
			tenantID, userID)
		return e
	})
	if err != nil {
		return err
	}
	userGenCache.Delete(tenantID.String() + ":" + userID.String())
	return nil
}

// BumpTenantGeneration increments a tenant's generation — one O(1) atomic write kills EVERY session in the tenant
// (offboard). Cache-busts so it's immediate on this node.
func (s *Service) BumpTenantGeneration(ctx context.Context, tenantID uuid.UUID) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO tenant_session_state (tenant_id, generation) VALUES ($1,1)
			 ON CONFLICT (tenant_id) DO UPDATE SET generation = tenant_session_state.generation + 1, updated_at=now()`,
			tenantID)
		return e
	})
	if err != nil {
		return err
	}
	tenantGenCache.Delete(tenantID)
	return nil
}

// MintSession is the ONE path that stamps a session token with the current generation (MA-SR-9 — stamp
// completeness). Every login path (password, SSO via the sso.Directory interface, elevated) routes through it; a
// CI guard forbids any other caller of the token Manager's Issue*. Stamping resolves the current gen/tgen; a
// resolve error fails the mint (a token we can't stamp correctly is worse than a failed login, which retries).
// It stamps the passed principal (pointer) with the resolved gen/tgen, so the caller's principal reflects exactly
// what the issued token carries (a LoginResult.Principal thus matches its token).
func (s *Service) MintSession(ctx context.Context, p *auth.Principal, ttl time.Duration) (string, error) {
	// S1 force-MFA enforcement — the LIVE CONSUMER of the require_mfa policy + operator floor, at the single mint
	// chokepoint (so password login, SSO, and refresh are all covered; reachability, not one caller). An in-scope
	// user with no active MFA factor is refused a full session; the caller mints a restricted grace session so they
	// enroll instead of being locked out. A grace (MFAPending) mint is the ONE exception — it IS that escape hatch.
	// Service accounts (API keys) never mint sessions and are exempt defensively. (Removing this block is the exact
	// mfa.enforce regression — a mutation test asserts it goes RED, and check-mfa-enforcement-consumed.sh fails.)
	if !p.MFAPending && !p.ServiceAccount {
		required, mErr := s.mfaEnrollmentRequired(ctx, p)
		if mErr != nil {
			return "", httpx.ErrUnavailable("could not mint session (MFA policy unavailable)")
		}
		if required {
			return "", auth.ErrMFAEnrollmentRequired
		}
	}
	ugen, err := s.currentUserGen(ctx, p.TenantID, p.UserID)
	if err != nil {
		return "", httpx.ErrUnavailable("could not mint session (generation unavailable)")
	}
	tgen, err := s.currentTenantGen(ctx, p.TenantID)
	if err != nil {
		return "", httpx.ErrUnavailable("could not mint session (generation unavailable)")
	}
	p.Gen, p.TGen = ugen, tgen
	return s.tokens.IssueWithTTL(*p, ttl)
}

// checkSessionGeneration is the per-request revocation check (called from CheckSession). A machine principal
// (API key) is exempt — its lifecycle is key deletion. A token behind the current per-tenant OR per-user
// generation is REVOKED (401). A resolution failure is a TRANSIENT deny (503), not a session kill.
func (s *Service) checkSessionGeneration(ctx context.Context, p auth.Principal) error {
	if p.ServiceAccount {
		return nil
	}
	tgen, err := s.currentTenantGen(ctx, p.TenantID)
	if err != nil {
		return httpx.ErrUnavailable("session validation temporarily unavailable")
	}
	if p.TGen < tgen {
		return httpx.ErrUnauthorized("session revoked")
	}
	ugen, err := s.currentUserGen(ctx, p.TenantID, p.UserID)
	if err != nil {
		return httpx.ErrUnavailable("session validation temporarily unavailable")
	}
	if p.Gen < ugen {
		return httpx.ErrUnauthorized("session revoked")
	}
	return nil
}
