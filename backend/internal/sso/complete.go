package sso

import (
	"context"
	"errors"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// allowedSSORoles are the ONLY roles a tenant SSO connection may JIT-provision.
// Provider/privileged roles (platform_admin, soc_manager, analysts, detection_eng)
// are excluded so a tenant's customer_admin — who can manage that tenant's SSO —
// cannot register an IdP with default_role=platform_admin and mint a super-admin
// (privilege-escalation guard). Provider-role provisioning is a separate,
// platform-admin-only flow (not via customer SSO).
var allowedSSORoles = map[string]bool{
	string(auth.RoleCustomerViewer): true,
	string(auth.RoleCustomerAdmin):  true,
}

// ValidSSORole reports whether a role is safe to use as an SSO default_role.
func ValidSSORole(role string) bool { return allowedSSORoles[role] }

// completeSSO is the shared, security-critical tail of any SSO login (OIDC or
// SAML): link an existing user — which MUST belong to the connection's tenant — or
// JIT-provision one with the connection's default role, issue the Nirvet session
// token, and write the login to the audit trail (IAM-010). Both protocols call this
// so provisioning, tenant-binding and session issuance have ONE tested code path.
//
// The caller is responsible for having already verified the identity assertion
// (id_token / signed SAML assertion) and the email-domain allowlist before calling.
func completeSSO(ctx context.Context, dir Directory, tokens *auth.Manager, db *database.DB,
	tenantID uuid.UUID, email, defaultRole, action, target string, meta map[string]any) (*LoginResult, error) {

	created := false
	uid, tid, role, ok, err := dir.LookupForSSO(ctx, email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, httpx.ErrInternal("directory lookup failed")
	}
	if ok {
		// An existing account for this email must be in the connection's tenant —
		// never let one tenant's IdP mint a session for another tenant's user.
		if tid != tenantID {
			return nil, httpx.ErrForbidden("user belongs to a different tenant")
		}
	} else {
		// Defence in depth (R2 low): re-validate the connection's default_role at login,
		// so even a bad/legacy DB row (default_role=platform_admin) cannot JIT-mint a
		// privileged account here — not just at connection-create time.
		if !ValidSSORole(defaultRole) {
			return nil, httpx.ErrForbidden("SSO default_role is not a permitted customer role")
		}
		newID, perr := dir.ProvisionForSSO(ctx, tenantID, email, defaultRole)
		if perr != nil {
			return nil, httpx.ErrInternal("could not provision user")
		}
		uid, tid, role, created = newID, tenantID, defaultRole, true
	}

	p := auth.Principal{UserID: uid, TenantID: tid, Role: auth.Role(role), Email: email}
	token, terr := tokens.Issue(p)
	if terr != nil {
		return nil, httpx.ErrInternal("could not issue session")
	}

	if meta == nil {
		meta = map[string]any{}
	}
	meta["jit_created"] = created
	_ = db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: uid, ActorEmail: email, Action: action, Target: target, Metadata: meta,
		})
	})
	return &LoginResult{Token: token, Email: email, TenantID: tid, Created: created}, nil
}
