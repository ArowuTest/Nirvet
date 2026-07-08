package iam

// Role-grant policy shared by the surfaces that assign a role to a principal (service accounts,
// invitations). Centralised so the provider/customer domain guard cannot drift between them again
// (Round-4 H1: CreateServiceAccount was missing it, letting a customer_admin mint a provider-role
// API key — cross-domain BFLA).

import (
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

// knownRoles are the roles that may be GRANTED to a principal (service account, invitation) or
// TARGETED by an elevation. platform_admin is intentionally absent — it is never grantable via
// these self-service surfaces.
var knownRoles = map[auth.Role]bool{
	auth.RoleSOCManager: true, auth.RoleAnalystT1: true, auth.RoleAnalystT2: true,
	auth.RoleAnalystT3: true, auth.RoleDetectionEng: true,
	auth.RoleCustomerAdmin: true, auth.RoleCustomerViewer: true,
}

// validateGrantableRole enforces the role-grant boundary shared by service-account and invitation
// creation: (1) the target must be a known, non-admin grantable role (allowlist, not just a
// platform_admin block), and (2) an actor may not grant a PROVIDER (SOC) role unless the actor is
// itself provider-side — so a customer_admin can never mint a provider-role principal. A provider
// admin may still grant customer roles (MSSP operator provisioning a customer user).
//
// Elevation uses a stricter bidirectional same-domain check (validateTarget) instead, because it
// re-labels a user's OWN role rather than granting a role to another principal.
func validateGrantableRole(actor, target auth.Role) error {
	if target == auth.RolePlatformAdmin || !knownRoles[target] {
		return httpx.ErrBadRequest("role must be a grantable, non-admin role")
	}
	if !auth.IsProviderRole(actor) && auth.IsProviderRole(target) {
		return httpx.ErrForbidden("cannot grant a provider role across the provider/customer boundary")
	}
	return nil
}
