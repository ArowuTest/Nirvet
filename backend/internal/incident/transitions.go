package incident

// Incident stage state machine (SRS CASE-002) + closure criteria (CASE-009). The transitions are
// structural domain vocabulary (like the tenant status lifecycle), enforced fail-closed: an unlisted
// transition is rejected. Any active stage may reach 'closed' (a false positive can close early);
// 'closed' may reopen to 'investigating' or advance to 'post_incident_review'.

import (
	"strings"

	"github.com/ArowuTest/nirvet/internal/platform/httpx"
)

var stageTransitions = map[Stage][]Stage{
	StageNew:                {StageTriage, StageClosed},
	StageTriage:             {StageAssigned, StageInvestigating, StageClosed},
	StageAssigned:           {StageInvestigating, StageClosed},
	StageInvestigating:      {StageWaitingCustomer, StageContainmentPending, StageContained, StageClosed},
	StageWaitingCustomer:    {StageInvestigating, StageContainmentPending, StageClosed},
	StageContainmentPending: {StageContained, StageClosed},
	StageContained:          {StageEradication, StageClosed},
	StageEradication:        {StageRecovery, StageClosed},
	StageRecovery:           {StageMonitoring, StageClosed},
	StageMonitoring:         {StageClosed},
	StageClosed:             {StagePostIncidentReview, StageInvestigating}, // PIR, or reopen
	StagePostIncidentReview: {StageClosed},
}

// validStage reports whether s is a known stage.
func validStage(s Stage) bool { _, ok := stageTransitions[s]; return ok }

// canTransition reports whether from → to is an allowed stage transition (same-stage handled by the
// caller as an idempotent no-op).
func canTransition(from, to Stage) bool {
	for _, s := range stageTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// ClosureInput carries the CASE-009 closure criteria required to move an incident to 'closed'.
type ClosureInput struct {
	Disposition    Disposition `json:"disposition"`
	RootCause      string      `json:"root_cause"`
	Impact         string      `json:"impact"`
	ActionsTaken   string      `json:"actions_taken"`
	LessonsLearned string      `json:"lessons_learned"`
	CustomerAck    bool        `json:"customer_ack"`
}

// validate enforces the mandatory closure fields (CASE-009): a case can never be closed without a
// valid disposition, root cause, impact, and actions taken. lessons_learned + customer_ack are optional.
func (c ClosureInput) validate() error {
	if !validDisposition[c.Disposition] {
		return httpx.ErrBadRequest("disposition must be one of true_positive|false_positive|benign_true_positive|duplicate|not_applicable")
	}
	if strings.TrimSpace(c.RootCause) == "" {
		return httpx.ErrBadRequest("root_cause is required to close an incident")
	}
	if strings.TrimSpace(c.Impact) == "" {
		return httpx.ErrBadRequest("impact is required to close an incident")
	}
	if strings.TrimSpace(c.ActionsTaken) == "" {
		return httpx.ErrBadRequest("actions_taken is required to close an incident")
	}
	return nil
}
