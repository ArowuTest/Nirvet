package sso

import (
	"time"

	"github.com/google/uuid"
)

// SAMLConnection is a tenant's SAML 2.0 IdP configuration. The IdP certificate is
// the IdP's PUBLIC signing cert (used to validate the signed SAML Response) — not a
// secret, so it is not vault-sealed.
type SAMLConnection struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	IDPEntityID    string    `json:"idp_entity_id"`
	IDPSSOURL      string    `json:"idp_sso_url"`
	IDPCertificate string    `json:"idp_certificate"` // PEM, public
	SPEntityID     string    `json:"sp_entity_id"`
	ACSURL         string    `json:"acs_url"`
	EmailAttribute string    `json:"email_attribute"` // '' => use NameID
	DefaultRole    string    `json:"default_role"`
	EmailDomain    string    `json:"email_domain"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
}

// SAMLCreateInput configures a SAML connection.
type SAMLCreateInput struct {
	IDPEntityID    string `json:"idp_entity_id"`
	IDPSSOURL      string `json:"idp_sso_url"`
	IDPCertificate string `json:"idp_certificate"`
	SPEntityID     string `json:"sp_entity_id"`
	ACSURL         string `json:"acs_url"`
	EmailAttribute string `json:"email_attribute"`
	DefaultRole    string `json:"default_role"`
	EmailDomain    string `json:"email_domain"`
}
