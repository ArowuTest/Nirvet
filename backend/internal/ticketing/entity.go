// Package ticketing mirrors Nirvet incidents into a tenant's ITSM (ServiceNow or
// Jira) so the customer works cases in their own system of record (SRS §6.16, §8).
// It is outbound and product-configured (the tenant sets up the connection), and
// runs best-effort on the incident path — a ticketing outage never blocks incident
// creation. Credentials are vault-encrypted (ADR-0004); tenant-scoped (RLS).
package ticketing

import (
	"time"

	"github.com/google/uuid"
)

// Provider kinds.
const (
	ProviderServiceNow = "servicenow"
	ProviderJira       = "jira"
)

// Connection is a tenant's ITSM configuration.
type Connection struct {
	ID         uuid.UUID      `json:"id"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	Provider   string         `json:"provider"`
	BaseURL    string         `json:"base_url"`
	AuthUser   string         `json:"auth_user"`
	Credential []byte         `json:"-"` // vault-sealed; never serialised
	Config     map[string]any `json:"config"`
	Enabled    bool           `json:"enabled"`
	CreatedAt  time.Time      `json:"created_at"`
}

// CreateInput configures a ticketing connection. Credential is plaintext inbound;
// it is sealed before storage and never returned.
type CreateInput struct {
	Provider   string         `json:"provider"`
	BaseURL    string         `json:"base_url"`
	AuthUser   string         `json:"auth_user"`
	Credential string         `json:"credential"`
	Config     map[string]any `json:"config"`
}

// Ticket is the incident summary pushed to the ITSM.
type Ticket struct {
	Title       string
	Description string
	Severity    string
}

// Ref is the created external ticket's identifier and link.
type Ref struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}
