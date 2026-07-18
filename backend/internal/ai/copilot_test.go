package ai

import (
	"strings"
	"testing"
)

// copilotHistory turns prior turns into the untrusted history bag (one line per turn, speaker-labelled, in order).
// The NEW analyst message is NOT part of history — it flows separately as the redacted, answerable `question` bag
// (P0: the whole conversation goes through redaction; nothing is concatenated raw).
func TestCopilotHistory_LabelsAndOrder(t *testing.T) {
	history := []CopilotTurn{
		{Role: "user", Content: "what is this alert?"},
		{Role: "assistant", Content: "it looks like a brute-force attempt."},
	}
	got := copilotHistory(history)
	if len(got) != 2 {
		t.Fatalf("expected 2 history lines, got %d: %v", len(got), got)
	}
	if got[0] != "Analyst: what is this alert?" {
		t.Fatalf("first line mislabelled/ordered: %q", got[0])
	}
	if got[1] != "Copilot: it looks like a brute-force attempt." {
		t.Fatalf("second line mislabelled/ordered: %q", got[1])
	}
}

func TestCopilotHistory_Empty(t *testing.T) {
	if got := copilotHistory(nil); len(got) != 0 {
		t.Fatalf("empty history must yield no lines, got %v", got)
	}
}

// copilotTask is trusted framing (no customer data) that rides OUTSIDE the untrusted-data fence and tells the model
// the fenced block is data (incl. inert prior conversation) and to answer the labelled latest question.
func TestCopilotTask_IsTrustedFraming(t *testing.T) {
	if strings.Contains(copilotTask, "=") || strings.Contains(copilotTask, "\n") {
		t.Fatalf("copilotTask should be a single trusted instruction line: %q", copilotTask)
	}
	for _, want := range []string{"latest question", "never instruct anyone to take destructive action"} {
		if !strings.Contains(copilotTask, want) {
			t.Fatalf("copilotTask missing framing %q: %q", want, copilotTask)
		}
	}
}
