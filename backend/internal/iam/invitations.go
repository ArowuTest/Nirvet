package iam

// Temporary user invitation links (SRS §6.2 IAM-001/008). An admin invites a user by email +
// role; a one-time expiring token lets the invitee activate themselves (set a password). Only
// sha256(token) is stored; the raw token is shown once.

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

const inviteScheme = "nvi_"

// Invitation is the non-secret metadata of an invite (the token is never returned after creation).
type Invitation struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Email      string     `json:"email"`
	Role       auth.Role  `json:"role"`
	InvitedBy  string     `json:"invited_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// InviteInput creates an invitation.
type InviteInput struct {
	Email          string    `json:"email"`
	Role           auth.Role `json:"role"`
	ExpiresInHours int       `json:"expires_in_hours"`
}

func clampInviteHours(h int) int {
	if h <= 0 {
		h = 168 // 7 days
	}
	if h < 1 {
		h = 1
	}
	if h > 720 {
		h = 720 // 30 days
	}
	return h
}

// CreateInvitation issues a one-time invite and returns the RAW token exactly once. The role
// must be grantable (never platform_admin) and within the inviter's domain (a customer_admin
// cannot invite a provider/SOC role).
func (s *Service) CreateInvitation(ctx context.Context, p auth.Principal, tenantID uuid.UUID, in InviteInput) (*Invitation, string, error) {
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	if in.Email == "" || !strings.Contains(in.Email, "@") {
		return nil, "", httpx.ErrBadRequest("a valid email is required")
	}
	if in.Role == auth.RolePlatformAdmin || !knownRoles[in.Role] {
		return nil, "", httpx.ErrBadRequest("role must be a grantable, non-admin role")
	}
	if !auth.IsProviderRole(p.Role) && auth.IsProviderRole(in.Role) {
		return nil, "", httpx.ErrForbidden("cannot invite a provider role")
	}
	rb := make([]byte, 24)
	if _, err := rand.Read(rb); err != nil {
		return nil, "", httpx.ErrInternal("could not generate token")
	}
	raw := inviteScheme + hex.EncodeToString(rb)
	hash := sha256hex(raw)
	inv := &Invitation{ID: uuid.New(), TenantID: tenantID, Email: in.Email, Role: in.Role,
		InvitedBy: p.Email, ExpiresAt: time.Now().Add(time.Duration(clampInviteHours(in.ExpiresInHours)) * time.Hour)}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`INSERT INTO user_invitations (id, tenant_id, email, role, token_hash, invited_by, expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			inv.ID, tenantID, inv.Email, inv.Role, hash, p.Email, inv.ExpiresAt); e != nil {
			return e
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.invitation_create", Target: "invitation:" + inv.ID.String(),
			Metadata: map[string]any{"email": inv.Email, "role": inv.Role}})
	})
	if err != nil {
		return nil, "", httpx.ErrInternal("could not create invitation")
	}
	return inv, raw, nil
}

// ListInvitations returns the tenant's pending (unaccepted) invitations.
func (s *Service) ListInvitations(ctx context.Context, tenantID uuid.UUID) ([]Invitation, error) {
	var out []Invitation
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, email, role, invited_by, expires_at, accepted_at, created_at
			   FROM user_invitations WHERE accepted_at IS NULL ORDER BY created_at DESC LIMIT 500`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Invitation
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Email, &i.Role, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// RevokeInvitation deletes a pending invitation.
func (s *Service) RevokeInvitation(ctx context.Context, p auth.Principal, tenantID, id uuid.UUID) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM user_invitations WHERE id=$1 AND accepted_at IS NULL`, id)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: p.UserID, ActorEmail: p.Email,
			Action: "iam.invitation_revoke", Target: "invitation:" + id.String()})
	})
	if err == pgx.ErrNoRows {
		return httpx.ErrNotFound("invitation not found or already accepted")
	}
	if err != nil {
		return httpx.ErrInternal("could not revoke invitation")
	}
	return nil
}

// AcceptInvitation validates a raw invite token and provisions + activates the user in the
// invite's tenant, marking the invite accepted (one-time). Public: the pre-auth lookup uses the
// SECURITY DEFINER function. A duplicate email or an expired/accepted invite fails closed.
func (s *Service) AcceptInvitation(ctx context.Context, rawToken, password string) (*User, error) {
	if !strings.HasPrefix(rawToken, inviteScheme) {
		return nil, httpx.ErrUnauthorized("invalid invitation token")
	}
	if len(password) < 8 {
		return nil, httpx.ErrBadRequest("password must be at least 8 characters")
	}
	var (
		invID, tenantID uuid.UUID
		email, role     string
		expiresAt       time.Time
		acceptedAt      *time.Time
	)
	err := s.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, role, expires_at, accepted_at FROM auth_find_invitation_by_hash($1)`,
			sha256hex(rawToken)).Scan(&invID, &tenantID, &email, &role, &expiresAt, &acceptedAt)
	})
	if err != nil {
		return nil, httpx.ErrUnauthorized("invalid invitation token")
	}
	if acceptedAt != nil {
		return nil, httpx.ErrConflict("invitation already accepted")
	}
	if expiresAt.Before(time.Now()) {
		return nil, httpx.ErrConflict("invitation has expired")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, httpx.ErrInternal("could not set password")
	}
	u := &User{ID: uuid.New(), TenantID: tenantID, Email: email, Role: auth.Role(role), Status: UserActive}
	err = s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)`, email).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return errUserExists
		}
		if _, e := tx.Exec(ctx,
			`INSERT INTO users (id, tenant_id, email, password_hash, role, status) VALUES ($1,$2,$3,$4,$5,'active')`,
			u.ID, tenantID, email, hash, role); e != nil {
			return e
		}
		// Claim the invite (one-time): only the winner flips accepted_at.
		ct, e := tx.Exec(ctx, `UPDATE user_invitations SET accepted_at=now() WHERE id=$1 AND accepted_at IS NULL`, invID)
		if e != nil {
			return e
		}
		if ct.RowsAffected() != 1 {
			return errInviteRace
		}
		return audit.Record(ctx, tx, audit.Entry{ActorID: u.ID, ActorEmail: email,
			Action: "iam.invitation_accept", Target: "invitation:" + invID.String(),
			Metadata: map[string]any{"role": role}})
	})
	switch err {
	case nil:
		return u, nil
	case errUserExists:
		return nil, httpx.ErrConflict("a user with this email already exists")
	case errInviteRace:
		return nil, httpx.ErrConflict("invitation already accepted")
	default:
		return nil, httpx.ErrInternal("could not accept invitation")
	}
}

// sentinel errors for the accept transaction.
var (
	errUserExists = &sentinel{"user exists"}
	errInviteRace = &sentinel{"invite race"}
)

type sentinel struct{ s string }

func (e *sentinel) Error() string { return e.s }
