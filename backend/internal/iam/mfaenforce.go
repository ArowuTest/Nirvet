package iam

// S1 — Force-MFA server-side enforcement (go-live register B3). The LIVE CONSUMER of the require_mfa /
// mfa_required_roles policy + the operator instance floor. It is called at MintSession (the single mint
// chokepoint), so it covers password login, SSO, and refresh uniformly. This is what makes the policy real and
// not a decorative flag (the J5 mfa.enforce lesson): a mutation test that removes the MintSession call goes RED,
// and check-mfa-enforcement-consumed.sh asserts this consumer exists.

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The enrollment-required sentinel lives in the leaf auth package (auth.ErrMFAEnrollmentRequired) so both the mint
// owner here and the SSO login path recognise it without an import cycle.

// mfaGraceTTL bounds the restricted forced-enrollment grace session — long enough to enroll, short enough that a
// stalled enrollment doesn't linger. It is not a full session (MFAPending gates it to enroll/activate only).
const mfaGraceTTL = 15 * time.Minute

// privilegedMFARoles is the zero-config floor (2d): if a tenant arms require_mfa with an EMPTY role scope (and no
// instance floor covers them), MFA is enforced for these admin/mutating roles — never "protect no one". An
// armed-but-covers-nobody policy is the reader-no-writer failure; empty-scope must mean privileged, not allow-all.
var privilegedMFARoles = []auth.Role{
	auth.RolePlatformAdmin, auth.RoleSOCManager, auth.RoleDetectionEng, auth.RoleCustomerAdmin,
}

// mfaEnrollmentRequired reports whether principal p must have MFA before a FULL session may be minted. Effective
// required-role set = operator instance floor (all-roles, or a role list) ∪ the tenant's require_mfa scope
// (override-only-tightens — a tenant can add roles, never drop a floor role). A user who already has an active MFA
// factor is never enrollment-required. Fail-closed: a policy-read error propagates (MintSession denies), it never
// silently treats the read as "MFA not required".
func (s *Service) mfaEnrollmentRequired(ctx context.Context, p *auth.Principal) (bool, error) {
	var (
		tenantRequire bool
		tenantRoles   []string
		floorAll      bool
		floorRoles    []string
		userHasMFA    bool
	)
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Tenant policy (a missing row = seeded defaults: require_mfa=false).
		if e := tx.QueryRow(ctx, `SELECT require_mfa, mfa_required_roles FROM session_policies WHERE tenant_id=$1`,
			p.TenantID).Scan(&tenantRequire, &tenantRoles); e != nil && e != pgx.ErrNoRows {
			return e
		}
		// Operator instance floor (global singleton; readable in any context). A missing row = no floor.
		if e := tx.QueryRow(ctx, `SELECT require_all_roles, floor_roles FROM mfa_enforcement_floor WHERE id=1`).
			Scan(&floorAll, &floorRoles); e != nil && e != pgx.ErrNoRows {
			return e
		}
		// The user's active MFA factor. A missing user row → treat as no-MFA (fail toward enforcement, never
		// toward bypass); in production the user always exists (login/SSO just authenticated them).
		if e := tx.QueryRow(ctx, `SELECT mfa_enabled FROM users WHERE id=$1`, p.UserID).Scan(&userHasMFA); e != nil && e != pgx.ErrNoRows {
			return e
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if userHasMFA {
		return false, nil // already protected — never enrollment-required
	}
	if floorAll {
		return true, nil // operator floor: MFA mandatory for every role (Option 2 default)
	}
	required := make(map[string]bool, len(floorRoles)+len(tenantRoles)+len(privilegedMFARoles))
	for _, r := range floorRoles {
		required[r] = true
	}
	if tenantRequire {
		if len(tenantRoles) == 0 {
			for _, r := range privilegedMFARoles { // 2d zero-config floor
				required[string(r)] = true
			}
		}
		for _, r := range tenantRoles {
			required[r] = true
		}
	}
	return required[string(p.Role)], nil
}

// MintFullSessionAfterMFA promotes a restricted forced-enrollment grace session to a FULL session immediately
// after the user activates MFA — so they are not forced to re-login. It clears MFAPending and mints at the tenant's
// session TTL; because the user now has an active MFA factor, the MintSession enforcement check passes cleanly.
func (s *Service) MintFullSessionAfterMFA(ctx context.Context, p auth.Principal) (string, time.Duration, error) {
	p.MFAPending = false
	ttl := s.sessionTTL(ctx, p.TenantID)
	tok, err := s.MintSession(ctx, &p, ttl)
	return tok, ttl, err
}

// userHasActiveMFA is a small helper (used by tests / callers that already hold the principal) mirroring the read
// above; kept separate so intent is explicit at call sites.
func (s *Service) userHasActiveMFA(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	var on bool
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT mfa_enabled FROM users WHERE id=$1`, userID).Scan(&on)
	})
	return on, err
}
