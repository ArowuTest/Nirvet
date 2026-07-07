// Package alert is the analyst alert queue (SRS §6.8). Alerts are raised by
// detection from normalized events and can be assigned, triaged and promoted to
// incidents. All rows are tenant-scoped (RLS).
package alert

import (
	"time"

	"github.com/google/uuid"
)

// Status of an alert in the triage workflow.
type Status string

const (
	StatusNew      Status = "new"
	StatusAssigned Status = "assigned"
	StatusClosed   Status = "closed"   // false positive / handled
	StatusPromoted Status = "promoted" // converted to an incident
)

// Alert is a prioritised detection result awaiting triage.
type Alert struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	EventID     *uuid.UUID `json:"event_id,omitempty"`
	DetectionID *uuid.UUID `json:"detection_id,omitempty"`
	DedupeKey   string     `json:"dedupe_key"` // event_id:rule_id — one alert per (event, rule)
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Confidence  int        `json:"confidence"`
	Source      string     `json:"source"`
	Status      Status     `json:"status"`
	AssigneeID  *uuid.UUID `json:"assignee_id,omitempty"`
	ActorRef    string     `json:"actor_ref"`
	TargetRef   string     `json:"target_ref"`
	MITRE       []string   `json:"mitre,omitempty"`
	IncidentID  *uuid.UUID `json:"incident_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}
