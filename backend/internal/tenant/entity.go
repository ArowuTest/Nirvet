// Package tenant manages the customer/tenant registry (SRS §6.1). The tenants
// table is the platform-level registry (not itself RLS-scoped); access is limited
// to platform admins. isolation_tier drives the deployment model (ADR-0001).
package tenant

import (
	"time"

	"github.com/google/uuid"
)

// Service tiers (SRS §7).
type ServiceTier string

const (
	TierEssential  ServiceTier = "essential"
	TierStandard   ServiceTier = "standard"
	TierAdvanced   ServiceTier = "advanced"
	TierCritical   ServiceTier = "critical"
	TierEnterprise ServiceTier = "enterprise"
)

// Isolation tiers (ADR-0001).
type IsolationTier string

const (
	IsolationPooled    IsolationTier = "pooled"    // shared DB + RLS
	IsolationDedicated IsolationTier = "dedicated" // own database/instance
	IsolationSovereign IsolationTier = "sovereign" // in-region deployment
)

// validServiceTier / validIsolationTier gate Create against the enum sets (R6: no DB CHECK on these).
var validServiceTier = map[ServiceTier]bool{
	TierEssential: true, TierStandard: true, TierAdvanced: true, TierCritical: true, TierEnterprise: true,
}
var validIsolationTier = map[IsolationTier]bool{
	IsolationPooled: true, IsolationDedicated: true, IsolationSovereign: true,
}

// Status of a tenant.
type Status string

const (
	StatusOnboarding Status = "onboarding"
	StatusActive     Status = "active"
	StatusSuspended  Status = "suspended"
)

// Tenant is a customer/deployment partition.
type Tenant struct {
	ID            uuid.UUID     `json:"id"`
	Name          string        `json:"name"`
	Sector        string        `json:"sector"`
	Country       string        `json:"country"`
	ServiceTier   ServiceTier   `json:"service_tier"`
	IsolationTier IsolationTier `json:"isolation_tier"`
	Status        Status        `json:"status"`
	ExternalRef   string        `json:"external_ref,omitempty"` // operator's MDA id; batch idempotency key (empty = NULL)
	CreatedAt     time.Time     `json:"created_at"`
}
