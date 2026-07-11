package iam

// G1 admin-issued password reset (§6.2, Option 3). An authenticated admin issues a one-time, short-expiry reset
// token for a user in their tenant; the user consumes it to set a new password. There is NO public
// forgot-password endpoint and NO lookup-by-email, so the flow has no user-enumeration oracle — the token IS the
// capability. Mirrors the cleared invitation-token pattern (crypto/rand, sha256-stored, SD-fn pre-auth lookup,
// claim-then-act). RP-5 (kill the user's live sessions) is done ATOMICALLY with the password change via the
// session-generation bump.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	resetScheme = "nvr_"
	resetTTL    = 30 * time.Minute
)

// sentinel errors for the confirm transaction (mapped to safe HTTP codes by the caller).
var (
	errResetNoUser   = &sentinel{"user gone"}
	errResetInactive = &sentinel{"user inactive"}
	errResetSSO      = &sentinel{"sso-only"}
	errResetRace     = &sentinel{"token race"}
)

// ResetIssued is the non-secret result of issuing a reset (the token is never here unless the admin opted in).
type ResetIssued struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
	Emailed   bool      `json:"emailed"`
}

// IssuePasswordReset (ADMIN) mints a reset token for a user in tenantID. Authorization is the caller's — the route
// is tenant-scoped (platform_admin any tenant, customer_admin their own), and RP-1 additionally forbids resetting
// a user OUTSIDE the caller's role domain (a customer_admin cannot reset a provider/platform_admin). Only an
// ACTIVE, LOCAL-PASSWORD user can be reset (RP-6): an SSO-only or disabled account is refused (and a reset never
// re-enables a disabled account). The link is emailed by default; returnLink is an audited opt-in that also
// returns the raw link once for out-of-band delivery (account-takeover-capable — hence audited).
func (s *Service) IssuePasswordReset(ctx context.Context, p auth.Principal, tenantID, targetID uuid.UUID, returnLink bool) (*ResetIssued, string, error) {
	u, err := s.repo.GetByID(ctx, tenantID, targetID)
	if err != nil {
		return nil, "", httpx.ErrNotFound("user not found")
	}
	if err := validateGrantableRole(p.Role, u.Role); err != nil { // RP-1: role-domain boundary
		return nil, "", httpx.ErrForbidden("cannot reset a user outside your role domain")
	}
	if u.Status != UserActive { // RP-6
		return nil, "", httpx.ErrConflict("user is not active")
	}
	if u.PasswordHash == "" { // RP-6: SSO-only user has no local password to reset
		return nil, "", httpx.ErrConflict("user has no local password (SSO-managed)")
	}

	rb := make([]byte, 24)
	if _, err := rand.Read(rb); err != nil {
		return nil, "", httpx.ErrInternal("could not generate token")
	}
	raw := resetScheme + hex.EncodeToString(rb)
	hash := sha256hex(raw)
	res := &ResetIssued{UserID: u.ID, Email: u.Email, ExpiresAt: time.Now().Add(resetTTL)}

	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Single active reset: invalidate the user's other outstanding tokens first.
		if _, e := tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL`, u.ID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, issued_by, expires_at) VALUES ($1,$2,$3,$4,$5)`,
			tenantID, u.ID, hash, p.UserID, res.ExpiresAt); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.password_reset_issue", Target: "user:" + u.ID.String(),
			Metadata: map[string]any{"returned_to_admin": returnLink}})
	})
	if err != nil {
		return nil, "", httpx.ErrInternal("could not issue reset")
	}

	// RP-3: deliver via the outbox, link built from the SERVER-configured base URL (never a request host).
	if s.resetMailer != nil && s.resetBaseURL != "" {
		link := strings.TrimRight(s.resetBaseURL, "/") + "/reset-password?token=" + raw
		if e := s.resetMailer.NotifyPasswordReset(ctx, tenantID, u.Email, link); e == nil {
			res.Emailed = true
		}
	}
	if returnLink { // audited opt-in out-of-band fallback
		if s.resetBaseURL != "" {
			return res, strings.TrimRight(s.resetBaseURL, "/") + "/reset-password?token=" + raw, nil
		}
		return res, raw, nil
	}
	return res, "", nil
}

// ConfirmPasswordReset (PUBLIC) validates a raw token and sets the new password. No email lookup happens here, so
// there is no enumeration oracle — an invalid/expired/used token is a generic rejection. The whole state change
// (claim token, set password, invalidate the user's other tokens, BUMP the session generation to kill live
// sessions — RP-5, audit) is ONE transaction, so a reset can never leave the password changed but sessions alive.
// RP-6 is re-checked at CONFIRM time (authoritative): the account must still be active + local-password, so a
// reset cannot complete on an account disabled after the token was issued, and never re-enables one.
func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) error {
	if !strings.HasPrefix(rawToken, resetScheme) {
		return httpx.ErrUnauthorized("invalid reset token")
	}
	if len(newPassword) < 8 {
		return httpx.ErrBadRequest("password must be at least 8 characters")
	}
	var (
		id, tenantID, userID uuid.UUID
		expiresAt            time.Time
		usedAt               *time.Time
	)
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, user_id, expires_at, used_at FROM auth_find_password_reset_by_hash($1)`,
			sha256hex(rawToken)).Scan(&id, &tenantID, &userID, &expiresAt, &usedAt)
	})
	if err != nil {
		return httpx.ErrUnauthorized("invalid reset token")
	}
	if usedAt != nil {
		return httpx.ErrConflict("reset token already used")
	}
	if expiresAt.Before(time.Now()) {
		return httpx.ErrConflict("reset token has expired")
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return httpx.ErrInternal("could not set password")
	}

	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// RP-6 at confirm time (authoritative).
		var status string
		var hasPassword bool
		e := tx.QueryRow(ctx, `SELECT status, (password_hash <> '') FROM users WHERE id=$1`, userID).Scan(&status, &hasPassword)
		if e == pgx.ErrNoRows {
			return errResetNoUser
		}
		if e != nil {
			return e
		}
		if status != string(UserActive) {
			return errResetInactive
		}
		if !hasPassword {
			return errResetSSO
		}
		// Claim the token one-time (requester wins).
		ct, e := tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at=now() WHERE id=$1 AND used_at IS NULL`, id)
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return errResetRace
		}
		// Set the new password.
		if _, e := tx.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, userID, hash); e != nil {
			return e
		}
		// Invalidate the user's OTHER outstanding reset tokens.
		if _, e := tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL`, userID); e != nil {
			return e
		}
		// RP-5: bump the session generation IN THE SAME TX → the user's live sessions are revoked atomically with
		// the credential change (no window where the password changed but old sessions survive).
		if _, e := tx.Exec(ctx,
			`INSERT INTO user_session_state (tenant_id, user_id, generation) VALUES ($1,$2,1)
			 ON CONFLICT (tenant_id, user_id) DO UPDATE SET generation = user_session_state.generation + 1, updated_at=now()`,
			tenantID, userID); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: userID, ActorEmail: "",
			Action: "iam.password_reset_complete", Target: "user:" + userID.String()})
	})
	switch err {
	case nil:
		// Cache-bust so the revocation is immediate on this node (the tx wrote the generation directly).
		userGenCache.Delete(tenantID.String() + ":" + userID.String())
		return nil
	case errResetNoUser, errResetInactive, errResetSSO:
		return httpx.ErrConflict("this account cannot be reset")
	case errResetRace:
		return httpx.ErrConflict("reset token already used")
	default:
		return httpx.ErrInternal("could not complete reset")
	}
}
