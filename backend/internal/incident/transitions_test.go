package incident

import "testing"

// TestStageTransitions locks the CASE-002 state machine: the documented forward path and early-close
// are legal; skipping stages or advancing from a terminal state is rejected fail-closed.
func TestStageTransitions(t *testing.T) {
	legal := [][2]Stage{
		{StageNew, StageTriage},
		{StageTriage, StageInvestigating},
		{StageInvestigating, StageContainmentPending},
		{StageContainmentPending, StageContained},
		{StageContained, StageEradication},
		{StageEradication, StageRecovery},
		{StageRecovery, StageMonitoring},
		{StageMonitoring, StageClosed},
		{StageInvestigating, StageWaitingCustomer},
		{StageWaitingCustomer, StageInvestigating},
		{StageClosed, StagePostIncidentReview}, // PIR after close
		{StageClosed, StageInvestigating},      // reopen
		{StageTriage, StageClosed},             // early close (false positive)
	}
	for _, c := range legal {
		if !canTransition(c[0], c[1]) {
			t.Errorf("expected %s -> %s to be legal", c[0], c[1])
		}
	}
	illegal := [][2]Stage{
		{StageNew, StageContained},      // skip
		{StageClosed, StageEradication}, // resume from terminal
		{StageRecovery, StageInvestigating},
		{StageContained, StageTriage}, // go backwards
	}
	for _, c := range illegal {
		if canTransition(c[0], c[1]) {
			t.Errorf("expected %s -> %s to be ILLEGAL", c[0], c[1])
		}
	}
	// Every active stage can reach 'closed' (a case can be closed from anywhere).
	for from := range stageTransitions {
		if from == StageClosed {
			continue
		}
		if !canTransition(from, StageClosed) {
			t.Errorf("every active stage must be able to close: %s cannot", from)
		}
	}
}

// TestClosureValidation locks the CASE-009 mandatory closure criteria.
func TestClosureValidation(t *testing.T) {
	ok := ClosureInput{Disposition: DispFalsePositive, RootCause: "benign scanner", Impact: "none", ActionsTaken: "suppressed rule"}
	if err := ok.validate(); err != nil {
		t.Fatalf("a complete closure should validate: %v", err)
	}
	bad := []ClosureInput{
		{Disposition: "made_up", RootCause: "x", Impact: "y", ActionsTaken: "z"}, // invalid disposition
		{Disposition: DispTruePositive, Impact: "y", ActionsTaken: "z"},          // missing root_cause
		{Disposition: DispTruePositive, RootCause: "x", ActionsTaken: "z"},       // missing impact
		{Disposition: DispTruePositive, RootCause: "x", Impact: "y"},             // missing actions_taken
		{}, // empty
	}
	for i, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("case %d: expected closure validation to fail", i)
		}
	}
}
