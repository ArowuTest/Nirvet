package iam

// Access-review report (SRS §6.2 IAM-009): a single tenant-scoped view of who has access —
// human users (role, status, MFA, last login derived from the immutable audit trail), service
// accounts, pending invitations, and currently-active privileged elevations. Read-only.

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UserAccess is one human user's access posture.
type UserAccess struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	Role        auth.Role  `json:"role"`
	Status      string     `json:"status"`
	MFAEnabled  bool       `json:"mfa_enabled"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// AccessReview is the composed report.
type AccessReview struct {
	Users            []UserAccess     `json:"users"`
	ServiceAccounts  []ServiceAccount `json:"service_accounts"`
	PendingInvites   []Invitation     `json:"pending_invitations"`
	ActiveElevations []Elevation      `json:"active_elevations"`
}

// BuildAccessReview composes the tenant's access-review report.
func (s *Service) BuildAccessReview(ctx context.Context, tenantID uuid.UUID) (*AccessReview, error) {
	rep := &AccessReview{}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Users + last login derived from audit_log (both RLS-scoped to this tenant).
		rows, err := tx.Query(ctx,
			`SELECT u.id, u.email, u.role, u.status, u.mfa_enabled,
			        (SELECT max(at) FROM audit_log a WHERE a.actor_id = u.id AND a.action = 'auth.login')
			   FROM users u ORDER BY u.email`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ua UserAccess
			if err := rows.Scan(&ua.ID, &ua.Email, &ua.Role, &ua.Status, &ua.MFAEnabled, &ua.LastLoginAt); err != nil {
				return err
			}
			rep.Users = append(rep.Users, ua)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	// Compose the other facets (each tenant-scoped).
	if rep.ServiceAccounts, err = s.ListServiceAccounts(ctx, tenantID); err != nil {
		return nil, err
	}
	if rep.PendingInvites, err = s.ListInvitations(ctx, tenantID); err != nil {
		return nil, err
	}
	all, err := s.ListElevations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, e := range all {
		if e.Status == "active" { // ListElevations already applies derived expiry
			rep.ActiveElevations = append(rep.ActiveElevations, e)
		}
	}
	return rep, nil
}
