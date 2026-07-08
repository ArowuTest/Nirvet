// Package incident is case management (SRS §6.8): incidents, their lifecycle
// stages (doc 03 §5), and an investigation timeline. Tenant-scoped (RLS).
package incident

import (
	"time"

	"github.com/google/uuid"
)

// Stage in the incident lifecycle (doc 03 §5).
type Stage string

const (
	StageNew           Stage = "new"
	StageTriage        Stage = "triage"
	StageInvestigating Stage = "investigating"
	StageContained     Stage = "contained"
	StageClosed        Stage = "closed"
)

// Incident is a security case.
type Incident struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	Title     string     `json:"title"`
	Severity  string     `json:"severity"`
	Category  string     `json:"category"`
	Stage     Stage      `json:"stage"`
	OwnerID   *uuid.UUID `json:"owner_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`

	// SLA timers (SRS §6.8). Due-times are stamped at creation from the severity
	// policy; acknowledged_at on first ownership. The *Breached flags are derived on
	// read (not persisted).
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	AckDueAt        *time.Time `json:"ack_due_at,omitempty"`
	ResolveDueAt    *time.Time `json:"resolve_due_at,omitempty"`
	AckBreached     bool       `json:"ack_breached"`
	ResolveBreached bool       `json:"resolve_breached"`
}

// TimelineEntry is one event in an incident's investigation timeline.
type TimelineEntry struct {
	ID         uuid.UUID `json:"id"`
	IncidentID uuid.UUID `json:"incident_id"`
	At         time.Time `json:"at"`
	Author     string    `json:"author"`
	Kind       string    `json:"kind"` // note|status|action|evidence
	Note       string    `json:"note"`
}
