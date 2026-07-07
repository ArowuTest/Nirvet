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
