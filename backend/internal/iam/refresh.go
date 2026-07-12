package iam

// ADR-0007 rotating refresh tokens. A refresh token is an opaque 256-bit secret; only its sha256 is stored. It
// is ONE-TIME-USE: /auth/refresh redeems it (marks it used, mints a fresh access token + a successor refresh in
// the same family). Presenting an already-used token is treated as THEFT — the whole family is revoked
// (reuse detection). Rows carry the user/tenant session generation at issue, so a password change / offboard
// (generation bump) invalidates every outstanding refresh on next use. Mirrors the password_reset pre-auth
// pattern: SECURITY DEFINER hash lookup (no tenant context), then the mutation under WithTenant.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// refreshTokenTTL is how long a refresh chain may live before forcing a full re-login. Kept modest for a SOC
// console; tenant-configurable later (ADR-0007).
const refreshTokenTTL = 30 * 24 * time.Hour

var (
	errRefreshInvalid = errors.New("invalid refresh token")
	errRefreshReuse   = errors.New("refresh token reuse detected")
)

// newRefreshRaw returns a fresh 256-bit URL-safe secret.
func newRefreshRaw() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IssueRefresh mints a NEW refresh-token family for a principal (called at login / SSO callback). Returns the raw
// secret (to set in the httpOnly cookie) and its expiry.
func (s *Service) IssueRefresh(ctx context.Context, p auth.Principal) (raw string, expiresAt time.Time, err error) {
	ugen, err := s.currentUserGen(ctx, p.TenantID, p.UserID)
	if err != nil {
		return "", time.Time{}, err
	}
	tgen, err := s.currentTenantGen(ctx, p.TenantID)
	if err != nil {
		return "", time.Time{}, err
	}
	family := uuid.New()
	exp := time.Now().Add(refreshTokenTTL)
	err = s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		raw, err = s.insertRefreshTx(ctx, tx, p.TenantID, p.UserID, family, ugen, tgen, exp)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, exp, nil
}

// insertRefreshTx inserts one refresh row (new secret) and returns the raw secret. Runs inside a WithTenant tx.
func (s *Service) insertRefreshTx(ctx context.Context, tx pgx.Tx, tenantID, userID, family uuid.UUID, ugen, tgen int64, exp time.Time) (string, error) {
	raw, err := newRefreshRaw()
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO refresh_tokens (tenant_id, user_id, token_hash, family_id, user_gen, tenant_gen, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tenantID, userID, sha256hex(raw), family, ugen, tgen, exp)
	if err != nil {
		return "", err
	}
	return raw, nil
}

type refreshRow struct {
	id, tenantID, userID, family uuid.UUID
	userGen, tenantGen           int64
	usedAt, revokedAt            *time.Time
	expiresAt                    time.Time
}

// lookupRefresh reads a refresh row by raw secret via the pre-auth SD function (no tenant context).
func (s *Service) lookupRefresh(ctx context.Context, raw string) (refreshRow, error) {
	var r refreshRow
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, user_id, family_id, user_gen, tenant_gen, used_at, revoked_at, expires_at
			   FROM auth_find_refresh_by_hash($1)`, sha256hex(raw)).
			Scan(&r.id, &r.tenantID, &r.userID, &r.family, &r.userGen, &r.tenantGen, &r.usedAt, &r.revokedAt, &r.expiresAt)
	})
	return r, err
}

// revokeFamily revokes every live token in a family (reuse/theft response, or full logout).
func (s *Service) revokeFamily(ctx context.Context, tenantID, family uuid.UUID) {
	_ = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL`, family)
		return e
	})
}

// RedeemRefresh rotates a refresh token: validates it, mints a fresh access token, and issues a successor refresh
// in the same family. Returns the new access JWT, the new raw refresh secret, and the access TTL. On reuse of an
// already-rotated token, the whole family is revoked and an error is returned (theft response).
func (s *Service) RedeemRefresh(ctx context.Context, raw string) (accessToken, newRaw string, accessTTL time.Duration, err error) {
	r, lerr := s.lookupRefresh(ctx, raw)
	if lerr != nil {
		return "", "", 0, errRefreshInvalid
	}
	if r.revokedAt != nil || time.Now().After(r.expiresAt) {
		return "", "", 0, errRefreshInvalid
	}
	// Reuse of an already-rotated token = theft: revoke the whole chain.
	if r.usedAt != nil {
		s.revokeFamily(ctx, r.tenantID, r.family)
		return "", "", 0, errRefreshReuse
	}
	// Generation staleness: a password change / offboard invalidates the chain.
	if ugen, e := s.currentUserGen(ctx, r.tenantID, r.userID); e != nil {
		return "", "", 0, errRefreshInvalid
	} else if r.userGen < ugen {
		s.revokeFamily(ctx, r.tenantID, r.family)
		return "", "", 0, errRefreshInvalid
	}
	if tgen, e := s.currentTenantGen(ctx, r.tenantID); e != nil {
		return "", "", 0, errRefreshInvalid
	} else if r.tenantGen < tgen {
		s.revokeFamily(ctx, r.tenantID, r.family)
		return "", "", 0, errRefreshInvalid
	}

	curUgen, err := s.currentUserGen(ctx, r.tenantID, r.userID)
	if err != nil {
		return "", "", 0, errRefreshInvalid
	}
	curTgen, err := s.currentTenantGen(ctx, r.tenantID)
	if err != nil {
		return "", "", 0, errRefreshInvalid
	}

	var p auth.Principal
	txErr := s.db.WithTenant(ctx, r.tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Race-safe one-time claim: exactly one concurrent redeem wins.
		ct, e := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at=now() WHERE id=$1 AND used_at IS NULL`, r.id)
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return errRefreshReuse // lost the race → someone already rotated it (concurrent or replay)
		}
		// Reload the user: a disabled/deleted account cannot refresh.
		var role, email, status string
		if e := tx.QueryRow(ctx, `SELECT role, email, status FROM users WHERE id=$1`, r.userID).Scan(&role, &email, &status); e != nil {
			return errRefreshInvalid
		}
		if status != string(UserActive) {
			return errRefreshInvalid
		}
		p = auth.Principal{UserID: r.userID, TenantID: r.tenantID, Role: auth.Role(role), Email: email}
		// Successor refresh in the SAME family.
		nr, e := s.insertRefreshTx(ctx, tx, r.tenantID, r.userID, r.family, curUgen, curTgen, time.Now().Add(refreshTokenTTL))
		if e != nil {
			return e
		}
		newRaw = nr
		return nil
	})
	if txErr != nil {
		if errors.Is(txErr, errRefreshReuse) {
			s.revokeFamily(ctx, r.tenantID, r.family)
		}
		return "", "", 0, txErr
	}
	// Mint the fresh access token through the single chokepoint (stamps the current generation).
	accessTTL = s.sessionTTL(ctx, r.tenantID)
	tok, merr := s.MintSession(ctx, &p, accessTTL)
	if merr != nil {
		return "", "", 0, merr
	}
	return tok, newRaw, accessTTL, nil
}

// RevokeRefreshToken marks a single refresh token used (logout of one session). Best-effort; an unknown token is
// a no-op (idempotent logout).
func (s *Service) RevokeRefreshToken(ctx context.Context, raw string) {
	r, err := s.lookupRefresh(ctx, raw)
	if err != nil {
		return
	}
	_ = s.db.WithTenant(ctx, r.tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at=now() WHERE id=$1 AND used_at IS NULL`, r.id)
		return e
	})
}
