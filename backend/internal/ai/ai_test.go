package ai

import (
	"strings"
	"testing"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/google/uuid"
)

// The gateway must report unavailable (and a clear "offline" model id) when no API
// key is configured, so the platform runs without an LLM provider.
func TestGateway_AvailabilityAndModel(t *testing.T) {
	off := NewGateway("", "")
	if off.Available() {
		t.Fatal("gateway with no key must be unavailable")
	}
	if off.Model() != "offline-fallback" {
		t.Fatalf("offline model id = %q, want offline-fallback", off.Model())
	}
	on := NewGateway("sk-test", "claude-sonnet-5")
	if !on.Available() {
		t.Fatal("gateway with a key must be available")
	}
	if on.Model() != "claude-sonnet-5" {
		t.Fatalf("model id = %q", on.Model())
	}
}

// The offline fallback is the guardrail-critical path: it must restate OBSERVED
// evidence, never fabricate, and — most importantly — never tell the analyst to
// self-execute containment; it must route response through the approval workflow.
func TestFallbackSummary_AssistiveOnly_NoSelfExecution(t *testing.T) {
	a := &alert.Alert{
		ID:        uuid.New(),
		Title:     "Suspicious PowerShell",
		Severity:  "high",
		Source:    "microsoft-defender",
		ActorRef:  "user:cfo",
		TargetRef: "host:FIN-01",
		MITRE:     []string{"T1059.001"},
		Status:    alert.StatusNew,
	}
	got := fallbackSummary(a)

	// Restates observed evidence (no hallucination).
	for _, want := range []string{"OBSERVED", "high", "Suspicious PowerShell", "microsoft-defender", "user:cfo", "host:FIN-01", "T1059.001"} {
		if !strings.Contains(got, want) {
			t.Fatalf("fallback summary missing observed evidence %q\n---\n%s", want, got)
		}
	}
	// Routes response through the approval workflow (assistive-only guardrail).
	if !strings.Contains(strings.ToLower(got), "approval workflow") {
		t.Fatalf("summary must direct response through the approval workflow:\n%s", got)
	}
	// Must NOT instruct the analyst/AI to directly execute destructive actions.
	low := strings.ToLower(got)
	for _, banned := range []string{"i have isolated", "i isolated", "automatically contained", "executing containment", "i blocked"} {
		if strings.Contains(low, banned) {
			t.Fatalf("summary implies self-execution (%q) — violates assistive-only guardrail:\n%s", banned, got)
		}
	}
}

// A nil/empty MITRE must not break the deterministic summary (renders "n/a").
func TestFallbackSummary_HandlesEmptyMitre(t *testing.T) {
	a := &alert.Alert{Title: "x", Severity: "low", Source: "s", Status: alert.StatusNew}
	got := fallbackSummary(a)
	if !strings.Contains(got, "MITRE: n/a") {
		t.Fatalf("empty MITRE should render n/a:\n%s", got)
	}
	if !strings.Contains(got, "Actor: -") || !strings.Contains(got, "Target: -") {
		t.Fatalf("empty actor/target should render '-':\n%s", got)
	}
}

// The live system prompt must encode the assistive-only guardrails.
func TestSystemPrompt_EncodesGuardrails(t *testing.T) {
	low := strings.ToLower(systemPrompt)
	for _, want := range []string{"never take actions", "only the evidence", "observed", "approval workflow"} {
		if !strings.Contains(low, want) {
			t.Fatalf("system prompt missing guardrail phrase %q", want)
		}
	}
}
