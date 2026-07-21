package ai

// Falsification tests for AI-authored proposals (GATE_COPILOT_COMPLETION_I1_AI_PROPOSALS.md). The full egress
// round-trip (off-catalog rejected by CreateProposal, redaction holds, risk-advisory) is guarded by: the two AI
// fences (check-ai-no-direct-execution / check-ai-egress-redaction, both green), the REUSED CreateProposal validation
// (proposal_test.go: RejectsUnknownAction / RejectsInvalidRisk — DraftProposal creates through the SAME path), and the
// soar catalog-risk resolution (soar tests). These unit tests cover the pieces DraftProposal ADDS: the pre-egress
// fail-closed/decline paths (no provider needed) and the parse/citation-pruning helpers.

import (
	"context"
	"testing"

	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
)

func TestDraftProposal_FailsClosedWhenCatalogUnwired(t *testing.T) {
	// No action-catalog validator → the AI can't be bound to governed actions → refuse to draft (fail-closed),
	// BEFORE any grounding or egress. Mirrors CreateProposal's fail-closed stance.
	s := &Service{} // actionCatalog nil
	prop, reason, err := s.DraftProposal(context.Background(), auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}, uuid.New())
	if err == nil {
		t.Fatal("expected fail-closed error when the action catalog validator is unwired")
	}
	if prop != nil || reason != "" {
		t.Fatalf("expected no proposal and no decline on a hard error, got prop=%v reason=%q", prop, reason)
	}
}

func TestDraftProposal_DeclinesWhenNoActionsEnabled(t *testing.T) {
	// An empty catalog = no governed action to recommend → honest decline (not an error, not a fabricated action).
	s := &Service{actionCatalog: stubCatalog{keys: map[string]bool{}}}
	prop, reason, err := s.DraftProposal(context.Background(), auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}, uuid.New())
	if err != nil {
		t.Fatalf("expected a clean decline, got err=%v", err)
	}
	if prop != nil {
		t.Fatal("no action enabled must NOT produce a proposal")
	}
	if reason == "" {
		t.Fatal("expected a decline reason")
	}
}

func TestDraftProposal_DeclinesOnInsufficientEvidence(t *testing.T) {
	// Falsification #7 + the pre-egress honesty floor: with NO grounding sources wired, AssembleContext returns zero
	// facts → DraftProposal declines "insufficient evidence" BEFORE resolving a provider — so no egress is even
	// attempted (there is no provider on this Service, and reaching one would panic; not reaching one proves the point).
	s := &Service{actionCatalog: stubCatalog{keys: map[string]bool{"isolate_host": true}}} // incidents/alerts nil ⇒ empty context
	prop, reason, err := s.DraftProposal(context.Background(), auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}, uuid.New())
	if err != nil {
		t.Fatalf("expected a clean decline on thin evidence, got err=%v", err)
	}
	if prop != nil {
		t.Fatal("thin evidence must NOT produce a fabricated proposal")
	}
	if reason == "" {
		t.Fatal("expected an insufficient-evidence decline reason")
	}
}

func TestDraftProposal_RejectsNilIncident(t *testing.T) {
	s := &Service{actionCatalog: stubCatalog{keys: map[string]bool{"isolate_host": true}}}
	if _, _, err := s.DraftProposal(context.Background(), auth.Principal{TenantID: uuid.New(), UserID: uuid.New()}, uuid.Nil); err == nil {
		t.Fatal("expected a bad-request for a nil incident id")
	}
}

func TestKeepValidCitations(t *testing.T) {
	// Falsification #5 (structured form): the model's citation array is pruned to assembler-provided ids only — a
	// hallucinated id is dropped; duplicates and blanks are removed. An AI cannot cite evidence it was not given.
	valid := map[string]bool{"INC": true, "ALERT-1": true}
	got := keepValidCitations([]string{"INC", "ALERT-1", "ALERT-99", "", "INC", "EVT-7"}, valid)
	want := []string{"INC", "ALERT-1"}
	if len(got) != len(want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("kept %v, want %v", got, want)
		}
	}
	if len(keepValidCitations([]string{"NOPE-1", "FAKE"}, valid)) != 0 {
		t.Fatal("all-invalid citations must prune to empty")
	}
}

func TestExtractJSONObject(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"bare", `{"decline":false}`, `{"decline":false}`},
		{"prose_wrapped", "Sure! Here it is:\n{\"a\":1}\nHope that helps.", `{"a":1}`},
		{"code_fence", "```json\n{\"x\":2}\n```", `{"x":2}`},
		{"nested_braces", `{"a":{"b":1},"c":2}`, `{"a":{"b":1},"c":2}`},
		{"brace_in_string", `{"note":"has } brace","ok":true}`, `{"note":"has } brace","ok":true}`},
		{"none", "no json here", ""},
	}
	for _, c := range cases {
		if got := extractJSONObject(c.in); got != c.want {
			t.Errorf("%s: extractJSONObject(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestSortedActionKeys(t *testing.T) {
	got := sortedActionKeys(map[string]bool{"isolate_host": true, "block_ip": true, "disable_user": true})
	want := []string{"block_ip", "disable_user", "isolate_host"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedActionKeys = %v, want %v (deterministic order)", got, want)
		}
	}
}
