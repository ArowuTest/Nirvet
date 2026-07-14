package ai

import (
	"strings"
	"testing"
)

func TestBuildCopilotInstruction_FlattensHistoryInOrder(t *testing.T) {
	history := []CopilotTurn{
		{Role: "user", Content: "what is this alert?"},
		{Role: "assistant", Content: "it looks like a brute-force attempt."},
	}
	got := buildCopilotInstruction(history, "what should I do next?")

	// Prior turns appear in order, labelled by speaker; the new question is last, cued for the model.
	iAnalyst := strings.Index(got, "Analyst: what is this alert?")
	iCopilot := strings.Index(got, "Copilot: it looks like a brute-force attempt.")
	iNew := strings.Index(got, "Analyst: what should I do next?")
	if iAnalyst < 0 || iCopilot < 0 || iNew < 0 {
		t.Fatalf("missing lines in instruction: %q", got)
	}
	if !(iAnalyst < iCopilot && iCopilot < iNew) {
		t.Fatalf("history out of order: analyst=%d copilot=%d new=%d", iAnalyst, iCopilot, iNew)
	}
	if !strings.HasSuffix(got, "Copilot:") {
		t.Fatalf("instruction must end cueing the copilot, got tail: %q", got[len(got)-20:])
	}
}

func TestBuildCopilotInstruction_EmptyHistory(t *testing.T) {
	got := buildCopilotInstruction(nil, "hello")
	if !strings.Contains(got, "Analyst: hello") || !strings.HasSuffix(got, "Copilot:") {
		t.Fatalf("unexpected instruction: %q", got)
	}
}
