package ai

// §6.12 AI Governance slice A — domain types for the prompt registry, eval harness and output feedback.
// Grounds SRS AI-002 (grounding/citation), AI-003 (facts vs inferences), AI-005 (log prompts + feedback for model
// evaluation), AI-008 (safety tests: hallucination/unsafe/leakage/injection/unsupported), and §11 feedback labels.
// See build/GATE_AI_GOVERNANCE_SLICE_A.md.

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// --- Prompt registry ---

// PromptPurpose is the copilot task a prompt serves (constrained in the DB CHECK).
type PromptPurpose string

const (
	PurposeTriageSummary     PromptPurpose = "triage_summary"
	PurposeIncidentNarrative PromptPurpose = "incident_narrative"
	PurposeRootCause         PromptPurpose = "root_cause"
	PurposeNextSteps         PromptPurpose = "next_steps"
	PurposeReportDraft       PromptPurpose = "report_draft"
	PurposeTimelineExplain   PromptPurpose = "timeline_explain"
)

// PromptPurposes is the closed set (a new-prompt request is validated against it).
var PromptPurposes = map[PromptPurpose]bool{
	PurposeTriageSummary: true, PurposeIncidentNarrative: true, PurposeRootCause: true,
	PurposeNextSteps: true, PurposeReportDraft: true, PurposeTimelineExplain: true,
}

// Prompt is a logical, versioned copilot prompt.
type Prompt struct {
	ID          uuid.UUID     `json:"id"`
	Key         string        `json:"key"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Purpose     PromptPurpose `json:"purpose"`
	CreatedAt   time.Time     `json:"created_at"`
	// ActiveVersion is the current active version number (0 = none), joined for the list view.
	ActiveVersion int `json:"active_version"`
}

// PromptVersion is one immutable-once-published body + the model it was validated on.
type PromptVersion struct {
	ID        uuid.UUID  `json:"id"`
	PromptID  uuid.UUID  `json:"prompt_id"`
	Version   int        `json:"version"`
	Body      string     `json:"body"`
	Model     string     `json:"model"`
	Status    string     `json:"status"` // draft | active | archived
	Notes     string     `json:"notes"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// --- Eval harness ---

// EvalCategory is the AI-008 safety-test set, 1:1.
type EvalCategory string

const (
	CatGrounding        EvalCategory = "grounding"
	CatHallucination    EvalCategory = "hallucination"
	CatPromptInjection  EvalCategory = "prompt_injection"
	CatTenantLeakage    EvalCategory = "tenant_leakage"
	CatUnsupportedClaim EvalCategory = "unsupported_claim"
	CatFactual          EvalCategory = "factual"
)

// EvalCategories is the exhaustive AI-008 set; the seed suite must cover every one (M-1).
var EvalCategories = []EvalCategory{
	CatGrounding, CatHallucination, CatPromptInjection, CatTenantLeakage, CatUnsupportedClaim, CatFactual,
}

// EvalCriteria are the deterministic graded checks for a case (parsed from expected_json).
type EvalCriteria struct {
	// MustCite: every token must appear in the answer (grounding/citation, AI-002).
	MustCite []string `json:"must_cite,omitempty"`
	// MustNotContain: no token may appear (hallucination / injection canary / planted cross-tenant secret).
	MustNotContain []string `json:"must_not_contain,omitempty"`
	// MustRefuse: the answer must decline (insufficient-evidence behaviour).
	MustRefuse bool `json:"must_refuse,omitempty"`
}

// EvalCase is a golden (curated, synthetic) case. Context is the retrieved-evidence package given to the model.
type EvalCase struct {
	ID       uuid.UUID       `json:"id"`
	Suite    string          `json:"suite"`
	Name     string          `json:"name"`
	Category EvalCategory    `json:"category"`
	Context  json.RawMessage `json:"context"`
	Question string          `json:"question"`
	Expected EvalCriteria    `json:"expected"`
	Enabled  bool            `json:"enabled"`
}

// EvalRun is a single execution of the suite (optionally against a prompt's active version).
type EvalRun struct {
	ID            uuid.UUID    `json:"id"`
	Suite         string       `json:"suite"`
	PromptID      *uuid.UUID   `json:"prompt_id,omitempty"`
	PromptVersion *int         `json:"prompt_version,omitempty"`
	Judge         string       `json:"judge"`
	Total         int          `json:"total"`
	Passed        int          `json:"passed"`
	Failed        int          `json:"failed"`
	PassRate      float64      `json:"pass_rate"`
	CreatedBy     *uuid.UUID   `json:"created_by,omitempty"`
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    *time.Time   `json:"finished_at,omitempty"`
	Results       []EvalResult `json:"results,omitempty"`
}

// EvalResult is the per-case outcome within a run.
type EvalResult struct {
	CaseID    uuid.UUID    `json:"case_id"`
	Name      string       `json:"name"`
	Category  EvalCategory `json:"category"`
	Passed    bool         `json:"passed"`
	Score     float64      `json:"score"`
	Rationale string       `json:"rationale"`
}

// --- Feedback (SRS §11) ---

// FeedbackLabel is the analyst's judgement of a copilot output.
type FeedbackLabel string

const (
	FBUseful           FeedbackLabel = "useful"
	FBIncorrect        FeedbackLabel = "incorrect"
	FBUnsafe           FeedbackLabel = "unsafe"
	FBHallucinated     FeedbackLabel = "hallucinated"
	FBInsufficientEvid FeedbackLabel = "insufficient_evidence"
	FBAccepted         FeedbackLabel = "accepted"
	FBEdited           FeedbackLabel = "edited"
)

// FeedbackLabels is the closed §11 set.
var FeedbackLabels = map[FeedbackLabel]bool{
	FBUseful: true, FBIncorrect: true, FBUnsafe: true, FBHallucinated: true,
	FBInsufficientEvid: true, FBAccepted: true, FBEdited: true,
}

// Feedback is one label on a copilot output (tenant-scoped).
type Feedback struct {
	ID        uuid.UUID     `json:"id"`
	OutputRef string        `json:"output_ref"`
	Label     FeedbackLabel `json:"label"`
	Note      string        `json:"note"`
	CreatedBy *uuid.UUID    `json:"created_by,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}
