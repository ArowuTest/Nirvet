// Package asset is the asset inventory (SRS §6.15): a tenant's monitored hosts,
// users, services and cloud resources, each with a business criticality. Assets are
// matched to alerts/incidents by their canonical ref (the same actor_ref/target_ref
// the event pipeline carries), so a case can be enriched with what it actually
// affects and triaged by asset criticality. Tenant-scoped (RLS); Postgres is the
// system of record.
package asset

import (
	"time"

	"github.com/google/uuid"
)

// Kind classifies an asset.
type Kind string

const (
	KindHost    Kind = "host"
	KindUser    Kind = "user"
	KindService Kind = "service"
	KindCloud   Kind = "cloud"
	KindNetwork Kind = "network"
	KindOther   Kind = "other"
)

// Criticality is an asset's business importance (drives triage priority).
type Criticality string

const (
	CritLow      Criticality = "low"
	CritMedium   Criticality = "medium"
	CritHigh     Criticality = "high"
	CritCritical Criticality = "critical"
)

// Asset is one monitored entity in a tenant's inventory.
type Asset struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Ref         string    `json:"ref"` // canonical reference, e.g. host:FIN-01 / user:jane@acme.com
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Criticality string    `json:"criticality"`
	Owner       string    `json:"owner"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
}
