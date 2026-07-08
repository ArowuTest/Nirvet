// Package incident is case management (SRS §6.8): incidents, their lifecycle
// stages (doc 03 §5), and an investigation timeline. Tenant-scoped (RLS).
package incident

import (
	"time"

	"github.com/google/uuid"
)

// Stage in the incident lifecycle — the full SRS CASE-002 chain. The allowed transitions between
// stages are the stageTransitions state machine (transitions.go); this is the vocabulary.
type Stage string

const (
	StageNew                Stage = "new"
	StageTriage             Stage = "triage"
	StageAssigned           Stage = "assigned"
	StageInvestigating      Stage = "investigating"
	StageWaitingCustomer    Stage = "waiting_customer"
	StageContainmentPending Stage = "containment_pending"
	StageContained          Stage = "contained"
	StageEradication        Stage = "eradication"
	StageRecovery           Stage = "recovery"
	StageMonitoring         Stage = "monitoring"
	StageClosed             Stage = "closed"
	StagePostIncidentReview Stage = "post_incident_review"
)

// Disposition is the canonical SOC outcome vocabulary recorded at closure (CASE-009). Structural
// domain vocabulary (like severity/stage), not a per-tenant tunable.
type Disposition string

const (
	DispTruePositive       Disposition = "true_positive"
	DispFalsePositive      Disposition = "false_positive"
	DispBenignTruePositive Disposition = "benign_true_positive"
	DispDuplicate          Disposition = "duplicate"
	DispNotApplicable      Disposition = "not_applicable"
)

var validDisposition = map[Disposition]bool{
	DispTruePositive: true, DispFalsePositive: true, DispBenignTruePositive: true,
	DispDuplicate: true, DispNotApplicable: true,
}

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

	// Parent/child linking (CASE-006). ParentID points at an umbrella "major" incident; IsMajor
	// flags that this incident IS such an umbrella.
	ParentID *uuid.UUID `json:"parent_id,omitempty"`
	IsMajor  bool       `json:"is_major"`

	// Closure criteria (CASE-009), populated on the transition to 'closed'. Empty until then.
	Disposition    string `json:"disposition,omitempty"`
	RootCause      string `json:"root_cause,omitempty"`
	Impact         string `json:"impact,omitempty"`
	ActionsTaken   string `json:"actions_taken,omitempty"`
	LessonsLearned string `json:"lessons_learned,omitempty"`
	CustomerAck    bool   `json:"customer_ack"`

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
	Kind       string    `json:"kind"`       // note|status|action|evidence
	Visibility string    `json:"visibility"` // internal|customer (CASE-004); default internal
	Note       string    `json:"note"`
}

// visibility values (CASE-004).
const (
	VisibilityInternal = "internal"
	VisibilityCustomer = "customer"
)

// Task is an investigation task / checklist item on an incident (CASE-005).
type Task struct {
	ID          uuid.UUID  `json:"id"`
	IncidentID  uuid.UUID  `json:"incident_id"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	AssigneeID  *uuid.UUID `json:"assignee_id,omitempty"`
	Status      string     `json:"status"` // open|in_progress|done|cancelled
	DueAt       *time.Time `json:"due_at,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Task status vocabulary (CASE-005).
const (
	TaskOpen       = "open"
	TaskInProgress = "in_progress"
	TaskDone       = "done"
	TaskCancelled  = "cancelled"
)

var validTaskStatus = map[string]bool{
	TaskOpen: true, TaskInProgress: true, TaskDone: true, TaskCancelled: true,
}

// Attachment is an evidence file attached to an incident with chain-of-custody (CASE-008): the bytes
// live in the blob store, and SHA256 pins what was ingested so a later retrieval can be verified.
type Attachment struct {
	ID          uuid.UUID  `json:"id"`
	IncidentID  uuid.UUID  `json:"incident_id"`
	Filename    string     `json:"filename"`
	ContentType string     `json:"content_type"`
	SizeBytes   int64      `json:"size_bytes"`
	SHA256      string     `json:"sha256"`
	BlobURI     string     `json:"blob_uri"`
	Note        string     `json:"note,omitempty"`
	UploadedBy  *uuid.UUID `json:"uploaded_by,omitempty"`
	UploadedAt  time.Time  `json:"uploaded_at"`
}

// KBArticle is a knowledge-base article / runbook (CASE-010). Global (tenant nil) or tenant-owned.
type KBArticle struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Title     string     `json:"title"`
	Body      string     `json:"body,omitempty"`
	URL       string     `json:"url,omitempty"`
	Category  string     `json:"category,omitempty"`
	Tags      []string   `json:"tags"`
	CreatedAt time.Time  `json:"created_at"`
}

// Category is a configurable incident category template (CASE-007). Global (tenant nil) or tenant-custom.
type Category struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        *uuid.UUID `json:"tenant_id,omitempty"`
	Key             string     `json:"key"`
	Name            string     `json:"name"`
	Description     string     `json:"description,omitempty"`
	DefaultSeverity string     `json:"default_severity"`
	Enabled         bool       `json:"enabled"`
}
