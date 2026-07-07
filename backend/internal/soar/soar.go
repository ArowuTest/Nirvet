// Package soar is response orchestration (SRS §6.11; doc 04 §7). Playbooks run
// steps that may require approval and execute actions through connectors. The
// authority-to-act policy (doc 03 §6) gates every action — AI never executes
// destructive actions, only this engine under policy, with full audit.
//
// Action execution against real connectors (Defender isolate, Entra disable)
// requires live credentials; in this build a gated action is recorded as
// "simulated" with the connector/action it WOULD invoke, preserving the full
// approval + audit path.
package soar

import (
	"time"

	"github.com/google/uuid"
)

// AuthorityMode is the tenant authority-to-act level (doc 03 §6).
type AuthorityMode string

const (
	AuthorityObserve   AuthorityMode = "observe"        // recommend only
	AuthorityApproval  AuthorityMode = "approval"       // customer/SOC approves
	AuthorityPreAuth   AuthorityMode = "pre_authorised" // agreed low-risk actions auto-run
	AuthorityEmergency AuthorityMode = "emergency"      // critical-tier, contractual
)

// RiskClass of a SOAR action (doc 04 §9.5).
type RiskClass string

const (
	RiskLow      RiskClass = "low"
	RiskMedium   RiskClass = "medium"
	RiskHigh     RiskClass = "high"
	RiskCritical RiskClass = "critical"
)

// Step is one action in a playbook.
type Step struct {
	Name             string    `json:"name"`
	ConnectorKey     string    `json:"connector_key"`
	Action           string    `json:"action"`
	Risk             RiskClass `json:"risk"`
	RequiresApproval bool      `json:"requires_approval"`
}

// Playbook is a response workflow (global or tenant-owned).
type Playbook struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        *uuid.UUID `json:"tenant_id,omitempty"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	TriggerCategory string     `json:"trigger_category"`
	Steps           []Step     `json:"steps"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
}

// RunStatus of a playbook run.
type RunStatus string

const (
	RunPendingApproval RunStatus = "pending_approval"
	RunRunning         RunStatus = "running"
	RunCompleted       RunStatus = "completed"
	RunFailed          RunStatus = "failed"
	RunRejected        RunStatus = "rejected"
)

// StepResult is the recorded outcome of a step.
type StepResult struct {
	Name         string    `json:"name"`
	ConnectorKey string    `json:"connector_key"`
	Action       string    `json:"action"`
	Risk         RiskClass `json:"risk"`
	Status       string    `json:"status"` // executed | simulated | awaiting_approval | skipped
	Note         string    `json:"note"`
}

// PlaybookRun is an execution instance.
type PlaybookRun struct {
	ID          uuid.UUID    `json:"id"`
	TenantID    uuid.UUID    `json:"tenant_id"`
	PlaybookID  uuid.UUID    `json:"playbook_id"`
	IncidentID  *uuid.UUID   `json:"incident_id,omitempty"`
	Status      RunStatus    `json:"status"`
	Steps       []StepResult `json:"steps"`
	RequestedBy *uuid.UUID   `json:"requested_by,omitempty"`
	ApprovedBy  *uuid.UUID   `json:"approved_by,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	CompletedAt *time.Time   `json:"completed_at,omitempty"`
}

// Allowed reports whether an action of the given risk may auto-execute (without
// approval) under the tenant's authority mode. Higher risk requires approval.
func Allowed(mode AuthorityMode, risk RiskClass) bool {
	switch mode {
	case AuthorityObserve:
		return false
	case AuthorityApproval:
		return risk == RiskLow
	case AuthorityPreAuth:
		return risk == RiskLow || risk == RiskMedium
	case AuthorityEmergency:
		return risk != RiskCritical
	default:
		return false
	}
}
