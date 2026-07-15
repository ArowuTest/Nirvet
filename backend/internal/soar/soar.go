// Package soar is response orchestration (SRS §6.11; doc 04 §7). Playbooks run steps that may
// require approval; each step's §9.5 risk class comes from the admin-configurable action catalog,
// and the per-action authority-to-act policy (tenant.authority_policies) gates auto-execution. AI
// never executes destructive actions — only this engine, under policy, with full audit.
//
// Permitted steps dispatch through the ActionExecutor seam (executor.go). Actions with a registered
// real executor run for real (e.g. notify via the durable outbox); actions without one — notably the
// destructive connector containment actions, which need a live per-tenant Actioner registry that does
// not yet exist — record a TRUTHFUL "simulated" outcome naming what they would invoke, preserving the
// full authority + approval + audit path. business_critical (§9.5 Class 4) never auto-executes.
package soar

import (
	"time"

	"github.com/google/uuid"
)

// AuthorityMode is the tenant authority-to-act level (doc 03 §6).
type AuthorityMode string

const (
	AuthorityObserve  AuthorityMode = "observe"        // recommend only — nothing auto-runs. THIS is the fail-closed stop.
	AuthorityApproval AuthorityMode = "approval"       // customer/SOC approves
	AuthorityPreAuth  AuthorityMode = "pre_authorized" // agreed low-risk actions auto-run
	// AuthorityContractualAuto is the MOST PERMISSIVE mode: every risk class except business_critical auto-runs
	// with no human approval (see Allowed). It was called "emergency" until 0127 — a name that reads as an
	// emergency STOP and is the exact opposite of what it does. Renamed because it misled a reviewer of this very
	// package, and would mislead a platform_admin reaching for the brakes at 2am. The brake is AuthorityObserve.
	AuthorityContractualAuto AuthorityMode = "contractual_auto" // contractually pre-agreed autonomous execution
	// NOTE: spelling unified on "pre_authorized" (American) to match the per-action
	// authority policy store (tenant.authority_policies) that SOAR now consumes (Phase 0).
)

// RiskClass of a SOAR action — the canonical five-level SRS §9.5 scale (Class 0..4). The action
// catalog (soar_action_catalog) assigns each action a class; the engine gates auto-execution on it.
type RiskClass string

const (
	RiskInformational    RiskClass = "informational"     // Class 0 — enrich, note; no approval
	RiskLow              RiskClass = "low"               // Class 1 — ticket, notify analyst, watchlist
	RiskMedium           RiskClass = "medium"            // Class 2 — customer notify, password reset
	RiskHigh             RiskClass = "high"              // Class 3 — disable user, isolate, block
	RiskBusinessCritical RiskClass = "business_critical" // Class 4 — network block, mass quarantine, cloud lockdown
)

// validRiskClass is the set the catalog CHECK constraint enforces (kept in sync with migration 0036).
var validRiskClass = map[RiskClass]bool{
	RiskInformational: true, RiskLow: true, RiskMedium: true, RiskHigh: true, RiskBusinessCritical: true,
}

// riskRank orders the §9.5 classes (higher = more dangerous). Used to CLAMP a tenant catalog
// override so it can only RAISE an action's risk, never lower it (Round-4 M1: config may only
// tighten a safety guarantee). An unknown class ranks as max (fail-closed).
func riskRank(c RiskClass) int {
	switch c {
	case RiskInformational:
		return 0
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskBusinessCritical:
		return 4
	default:
		return 4
	}
}

// Step is one action in a playbook.
type Step struct {
	Name             string    `json:"name"`
	ConnectorKey     string    `json:"connector_key"`
	Action           string    `json:"action"`
	Risk             RiskClass `json:"risk"`
	RequiresApproval bool      `json:"requires_approval"`
	// Target is the entity a connector containment step acts on (host:/user:/ip:) — passed to the
	// Actioner in slice B. Optional; empty for internal/notify steps (§6.11 slice B).
	Target string `json:"target,omitempty"`

	// Control-flow (#187 slice B, MINIMAL — inline path only). ContinueOnFailure: if this step's EXECUTION
	// fails, keep running the rest of the run instead of halting (default false = halt-on-failure). It governs
	// EXECUTION failures ONLY — never an approval denial (a denied destructive step always halts). Condition
	// gates whether this step runs at all, based on a PRIOR step's recorded outcome — it may only SKIP a step,
	// never elevate/bypass approval or auto-run a destructive step. Conditions are honored on the INLINE path
	// only; the authoring API 400s a condition on/referencing a connector (supervised) step so a gating
	// condition is NEVER silently ignored at run time (supervised-step conditions → #181).
	ContinueOnFailure bool           `json:"continue_on_failure,omitempty"`
	Condition         *StepCondition `json:"condition,omitempty"`
}

// StepCondition gates a step on a PRIOR step's recorded outcome (skip-only). WhenStep names an earlier step in
// the same playbook; the step runs only if that prior step's recorded StepResult.Status equals EqualsStatus
// (e.g. "executed"). A minimal, unambiguous prior-outcome gate; richer field-level outcomes are #181.
type StepCondition struct {
	WhenStep     string `json:"when_step"`
	EqualsStatus string `json:"equals_status"`
}

// conditionMet reports whether a step's condition is satisfied given the results of prior steps ALREADY produced
// in this execution pass. Fail-closed: if the referenced prior step has not been resolved earlier in this pass
// (not found / still pending), the condition is UNMET — a gated step never runs unless its named precondition
// actually reached the asserted status. A nil condition is always met.
func conditionMet(prior []StepResult, c *StepCondition) bool {
	if c == nil {
		return true
	}
	for i := range prior {
		if prior[i].Name == c.WhenStep {
			return prior[i].Status == c.EqualsStatus
		}
	}
	return false
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

// ActionRecord is a durable record written by an internal, non-destructive executor (#187 slice C).
type ActionRecord struct {
	ID         uuid.UUID  `json:"id"`
	IncidentID *uuid.UUID `json:"incident_id,omitempty"`
	ActionKey  string     `json:"action_key"`
	Kind       string     `json:"kind"`
	Summary    string     `json:"summary"`
	CreatedAt  time.Time  `json:"created_at"`
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

// Allowed reports whether an action of the given §9.5 risk class may auto-execute (without human
// approval) under the tenant's authority-to-act mode. The rule set (SOAR-004/005, §9.5):
//   - business_critical (Class 4) NEVER auto-executes under ANY mode — the §9.5 "no full autonomous
//     execution in MVP/V1" guarantee, enforced in code so no misconfiguration can bypass it.
//   - observe: nothing auto-runs (recommend-only) — fully fail-closed. THIS is the stop.
//   - approval: only informational + low auto-run; medium/high await approval.
//   - pre_authorized: informational + low + medium auto-run (agreed lower-risk containment).
//   - contractual_auto: everything except business_critical auto-runs (contractual high-impact response) — the
//     MOST PERMISSIVE mode. Named "emergency" until 0127, which read as its own opposite.
func Allowed(mode AuthorityMode, risk RiskClass) bool {
	if risk == RiskBusinessCritical {
		return false // Class 4: incident-commander + customer authority only, never autonomous
	}
	switch mode {
	case AuthorityObserve:
		return false
	case AuthorityApproval:
		return risk == RiskInformational || risk == RiskLow
	case AuthorityPreAuth:
		return risk == RiskInformational || risk == RiskLow || risk == RiskMedium
	case AuthorityContractualAuto:
		return true // all but business_critical (handled above)
	default:
		return false
	}
}
