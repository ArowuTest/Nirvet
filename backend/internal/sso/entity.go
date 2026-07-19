// Package sso implements Single Sign-On via OIDC (SRS §6.2 IAM-001). Each tenant
// configures its own IdP connection; users authenticate at that IdP and are
// just-in-time provisioned into the tenant. The client secret is vault-encrypted
// (ADR-0004) and the id_token is verified against the IdP JWKS. Tenant-scoped (RLS);
// the unauthenticated callback resolves a connection via a SECURITY DEFINER lookup.
package sso

import (
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

// Connection is a tenant's OIDC IdP configuration.
type Connection struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Protocol     string    `json:"protocol"` // oidc
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	ClientSecret []byte    `json:"-"` // vault-sealed; never serialised
	RedirectURI  string    `json:"redirect_uri"`
	DefaultRole  string    `json:"default_role"`
	EmailDomain  string    `json:"email_domain"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// CreateInput is the payload to configure an OIDC connection. Secret is plaintext
// on the way in; it is sealed before storage and never returned.
type CreateInput struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	DefaultRole  string `json:"default_role"`
	EmailDomain  string `json:"email_domain"`
}

// LoginResult is returned to the caller after a successful SSO callback.
type LoginResult struct {
	Token     string         `json:"token"`
	Email     string         `json:"email"`
	TenantID  uuid.UUID      `json:"tenant_id"`
	Created   bool           `json:"created"` // true if the user was JIT-provisioned
	Principal auth.Principal `json:"-"`       // for cookie-based session issuance (ADR-0007)
	AccessTTL time.Duration  `json:"-"`       // access-cookie lifetime
	// MFAEnrollmentRequired is true when Token is a RESTRICTED forced-enrollment grace session (S1 force-MFA): the
	// SSO login succeeded but the user is in-scope for mandatory MFA with no active factor. The grace cookie is set;
	// the SPA reaches only MFA enroll/activate (every other route 403s) until MFA is active.
	MFAEnrollmentRequired bool `json:"mfa_enrollment_required,omitempty"`
}
