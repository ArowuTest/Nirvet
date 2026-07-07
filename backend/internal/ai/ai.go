// Package ai is the AI SOC copilot (SRS §6.12; doc 04). It is ASSISTIVE ONLY:
// it summarises, suggests and drafts — it never executes containment (only soar
// does, under approval). Every AI call is tenant-scoped (retrieval only from the
// tenant's own data), guarded, and logged (model + output) to the audit trail.
package ai

// Summary is an evidence-linked AI output that distinguishes observed fact from
// inference (doc 04 §3 guardrail: no unlabelled hallucination).
type Summary struct {
	Text       string   `json:"text"`
	Confidence string   `json:"confidence"` // observed | inferred | uncertain
	Model      string   `json:"model"`
	Evidence   []string `json:"evidence"` // references the AI was given
	Assistive  bool     `json:"assistive"`
}

// Guardrail names the controls every AI feature must satisfy (doc 04 §3).
type Guardrail string

const (
	GuardTenantIsolation Guardrail = "tenant_isolation"    // no cross-tenant retrieval
	GuardNoAutoContain   Guardrail = "no_auto_containment" // cannot execute actions
	GuardEvidenceLinked  Guardrail = "evidence_linked"     // separate observed vs inferred
	GuardHumanApproval   Guardrail = "human_approval"      // outbound needs sign-off
	GuardFullAudit       Guardrail = "full_audit"          // log model + output + decision
)

// systemPrompt encodes the guardrails for the live model.
const systemPrompt = `You are Nirvet's SOC analyst copilot. You assist human analysts; you never take actions.
Rules:
- Use ONLY the evidence provided. Do not invent facts, hostnames, users, or IOCs.
- Clearly separate what is OBSERVED in the evidence from what is INFERENCE.
- Be concise and operational: what happened, why it matters, and suggested next investigative steps.
- Never recommend executing destructive actions yourself; recommend they be run via the approval workflow.`
