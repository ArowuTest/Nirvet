package ai

// Falsification tests for agentic investigation (GATE_COPILOT_COMPLETION_I2_AGENTIC.md). The security properties that
// live in RunHunt — no-escalation (runs as `p`), no-raw-query (allow-list compiler), redaction (completeExternal),
// cost ceiling, tenant scope, read-audit — are verified in the investigation + redaction suites and reused verbatim
// (the adapter calls RunHunt with the analyst's principal; check-ai-egress-redaction stays green). These unit tests
// cover the pieces THIS increment adds: the closed read-only tool set (#5), the bounded-loop cap (#4), and the
// tool-call parser that decides run-a-hunt vs. answer.

import (
	"strings"
	"testing"
)

func TestAgentTools_ClosedReadOnlySet(t *testing.T) {
	// Falsification #5: the tool registry is a closed, read-only allowlist. The only tool is run_hunt; NO tool name may
	// imply a write/execute/mutate/soar action (the check-ai-tool-registry fence enforces this structurally too).
	if len(agentTools) != 1 || !agentTools[agentToolRunHunt] {
		t.Fatalf("agentTools must be exactly {%q}; got %v", agentToolRunHunt, agentTools)
	}
	forbidden := []string{"isolate", "disable", "block", "delete", "remove", "create", "update", "write", "execute",
		"contain", "quarantine", "kill", "reset", "rotate", "approve", "accept", "run_playbook"}
	for name := range agentTools {
		for _, bad := range forbidden {
			if strings.HasPrefix(name, bad) {
				t.Fatalf("agentic tool %q looks like a write/execute tool — read agency only", name)
			}
		}
	}
}

func TestMaxAgentToolCalls_Bounded(t *testing.T) {
	// Falsification #4: the loop is hard-capped, small — never unbounded iteration.
	if maxAgentToolCalls <= 0 || maxAgentToolCalls > 5 {
		t.Fatalf("maxAgentToolCalls must be a small positive bound, got %d", maxAgentToolCalls)
	}
	if maxAgentHuntFacts <= 0 {
		t.Fatalf("maxAgentHuntFacts must bound accumulated egress, got %d", maxAgentHuntFacts)
	}
}

func TestParseAgentToolCall(t *testing.T) {
	cases := []struct {
		name, in string
		wantTool string
		wantOK   bool
	}{
		{"valid_run_hunt", `{"tool":"run_hunt","all":[{"field":"severity","op":"eq","value":"high"}],"lookback_hours":24}`, "run_hunt", true},
		{"prose_answer", "Based on the evidence, the actor pivoted to host-02. No further hunt needed.", "", false},
		{"json_without_tool", `{"answer":"done","confidence":0.8}`, "", false},
		{"tool_wrapped_in_prose", "Let me check: {\"tool\":\"run_hunt\",\"any\":[]}", "run_hunt", true},
		{"empty", "", "", false},
	}
	for _, c := range cases {
		got, ok := parseAgentToolCall(c.in)
		if ok != c.wantOK || got.Tool != c.wantTool {
			t.Errorf("%s: parseAgentToolCall(%q) = (%q,%v), want (%q,%v)", c.name, c.in, got.Tool, ok, c.wantTool, c.wantOK)
		}
	}
}

func TestRegistryFieldNames_VocabularyOnly(t *testing.T) {
	// The vocabulary offered to the model is the code-owned registry — lowercase field names only, no raw/SQL tokens
	// (the compiler is the real gate; this asserts we never hand the model a non-field to try).
	for _, f := range registryFieldNames() {
		if f == "" || f != lowerASCII(f) {
			t.Fatalf("registry field %q is not a plain lowercase field name", f)
		}
	}
}

func TestAppendCapped(t *testing.T) {
	var facts []CitedFact
	for i := 0; i < 10; i++ {
		facts = appendCapped(facts, CitedFact{ID: "X", Fact: "y"}, 4)
	}
	if len(facts) != 4 {
		t.Fatalf("appendCapped did not cap: got %d, want 4", len(facts))
	}
}

func lowerASCII(s string) string { return strings.ToLower(s) }
