package connector

import (
	"time"

	"github.com/google/uuid"
)

// Kind of connector.
type Kind string

const (
	KindMicrosoft365 Kind = "microsoft-365"
	KindEntraID      Kind = "entra-id"
	KindDefender     Kind = "defender"
	KindSyslog       Kind = "syslog"
	KindWebhook      Kind = "webhook"
	// §6.4/§6.5 #118 host telemetry: an open agent (osquery/Wazuh) forwards host events into the EXISTING push
	// collector. This is INGESTION of customer-deployed open-agent telemetry, NOT a first-party endpoint agent
	// (SRS §1.4 scopes that out) — the kind only selects the source normalizer.
	KindOsquery Kind = "host_osquery"
	KindWazuh   Kind = "host_wazuh"
	// §6.11 G1 first non-Microsoft response vendor: Okta identity containment (suspend/unsuspend/revoke-sessions).
	// Ingestion for Okta already exists (source normalizer); this Kind selects the outbound Actioner client.
	KindOkta Kind = "okta"
)

// ConnectorConfig is a tenant's configured integration. Secrets are stored
// vault-encrypted and never returned; webhook connectors expose their source key
// exactly once at creation.
type ConnectorConfig struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	Kind        Kind           `json:"kind"`
	Name        string         `json:"name"`
	Direction   string         `json:"direction"`
	Enabled     bool           `json:"enabled"`
	Config      map[string]any `json:"config"`
	Health      string         `json:"health"`
	LastSuccess *time.Time     `json:"last_success,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}
