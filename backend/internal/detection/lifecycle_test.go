package detection

import "testing"

func TestValidStageAndCreateStage(t *testing.T) {
	for _, s := range []string{StageDraft, StagePeerReview, StageQA, StagePilot, StageProduction, StageTuned, StageRetired} {
		if !validStage(s) {
			t.Fatalf("%s should be a valid stage", s)
		}
	}
	if validStage("shipped") || validStage("") {
		t.Fatal("invalid stages must be rejected")
	}
	// createStage: only draft or production (default) may be authored directly.
	if st, err := createStage(""); err != nil || st != StageProduction {
		t.Fatalf("empty create stage should default to production: %s %v", st, err)
	}
	if st, err := createStage(StageDraft); err != nil || st != StageDraft {
		t.Fatalf("draft create stage should be allowed: %s %v", st, err)
	}
	if _, err := createStage(StagePilot); err == nil {
		t.Fatal("creating directly into pilot must be rejected")
	}
}

func TestStageTransitions(t *testing.T) {
	// The promotion path is reachable step by step.
	path := []string{StageDraft, StagePeerReview, StageQA, StagePilot, StageProduction, StageTuned}
	for i := 0; i+1 < len(path); i++ {
		if !stageTransitions[path[i]][path[i+1]] {
			t.Fatalf("expected %s -> %s to be allowed", path[i], path[i+1])
		}
	}
	// Skipping stages is not allowed (draft cannot jump to production without emergency).
	if stageTransitions[StageDraft][StageProduction] {
		t.Fatal("draft -> production must not be a normal transition")
	}
	// Any stage can retire; retired can reopen to draft.
	if !stageTransitions[StagePilot][StageRetired] || !stageTransitions[StageRetired][StageDraft] {
		t.Fatal("retire + reopen transitions expected")
	}
}
