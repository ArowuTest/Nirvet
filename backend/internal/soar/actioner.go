package soar

// §6.11 slice B — the connector Actioner registry (MUST-1). A destructive containment action (isolate
// host, disable user, block IP) is performed OUT of the run's DB transaction (Phase B of the two-phase
// model). The whole crash-safety + reversibility story rests on two properties, so they are DECLARED at
// registration as data, not left to prose the engine trusts:
//
//   - Idempotent || PreCheck — safe to re-drive after a crash (the reaper relies on this).
//   - Reversible + Inverse    — a Class3+ action must declare its undo (MUST-3 reverse).
//
// canAutoRun enforces the contract: the engine REFUSES to auto-run any connector action that fails it,
// forcing it to awaiting_customer (human confirm) instead. So "the Actioner is idempotent/reversible" is
// guaranteed by the registration contract, caught at wiring — not the first time it double-fires in prod.

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// ActionCorrelatorParam is the params key under which the supervisor injects a STABLE per-step correlator
// (run_id:step_index — identical across the first attempt and any crash-resume of the same step). It is the
// OWN-vs-FOREIGN attribution mechanism for a PreCheck destructive Actioner (MUST-3, round #34 H-1b): the
// Actioner MUST embed this correlator in the external action's audit trail / comment when it EXECUTES, and
// when a PreCheck finds an already-active action it MUST return prior_state.changed=true ONLY if that action
// carries THIS correlator (ours → reverse may undo it), false otherwise (a foreign pre-existing effect →
// reverse must NEVER undo it). Attributing by "is this a resume" is a fail-open: the claim proves we CLAIMED
// (Phase A), not that we caused the external effect (Phase B).
const ActionCorrelatorParam = "nirvet.correlator"

// Actioner performs one real connector action (Phase B) and declares the safety properties the engine
// enforces. Fn runs OUTSIDE any DB transaction: it makes the external call with vault-decrypted creds
// (netsafe.SafeClient — CI-enforced) and returns a connector reference plus the OBSERVED prior state
// (MUST-3) so a later reverse only undoes what actually changed. A PreCheck destructive Actioner MUST
// attribute own-vs-foreign via ActionCorrelatorParam (see its doc) so reverse never undoes a foreign effect.
type Actioner struct {
	ConnectorKey string
	Action       string
	Idempotent   bool   // re-running has no additional effect
	PreCheck     bool   // reads current state first, so a re-run is a no-op when already in target state
	Reversible   bool   // has a defined undo
	Inverse      string // action_key of the undo (required when Reversible)
	// Fn performs the effect. creds are the vault-decrypted connector credentials; target is the entity
	// (host/user/ip); returns (connector reference, observed prior state, error).
	Fn func(ctx context.Context, creds []byte, target string, params map[string]any) (ref string, priorState map[string]any, err error)
}

// key is the registry key: connector_key + ":" + action.
func actionerKey(connectorKey, action string) string {
	return strings.ToLower(connectorKey) + ":" + strings.ToLower(action)
}

// ActionerRegistry maps (connector_key, action) -> Actioner. Built once at wiring; read-only after.
type ActionerRegistry struct{ byKey map[string]Actioner }

// NewActionerRegistry builds an empty registry.
func NewActionerRegistry() *ActionerRegistry { return &ActionerRegistry{byKey: map[string]Actioner{}} }

// Register adds an Actioner. It validates the contract at wiring time: a reversible action must name its
// inverse, and (defensively) an action that is neither idempotent nor pre-checking is allowed to register
// but will never be auto-run (canAutoRun rejects it) — surfaced, not silently unsafe. Returns the registry
// for chaining; panics only on an outright contradictory declaration (reversible without inverse), because
// that is a programming error at wiring, not a runtime condition.
func (r *ActionerRegistry) Register(a Actioner) *ActionerRegistry {
	if a.Reversible && strings.TrimSpace(a.Inverse) == "" {
		panic("soar: Actioner " + a.ConnectorKey + ":" + a.Action + " declared Reversible without an Inverse action")
	}
	r.byKey[actionerKey(a.ConnectorKey, a.Action)] = a
	return r
}

// lookup returns the Actioner for a (connector_key, action), ok=false if none registered.
func (r *ActionerRegistry) lookup(connectorKey, action string) (Actioner, bool) {
	a, ok := r.byKey[actionerKey(connectorKey, action)]
	return a, ok
}

// canAutoRun reports whether a connector action may enter the automatic two-phase path, or must instead
// be withheld to human confirmation. This is the MUST-1 structural guard:
//   - not registered      → simulate (handled elsewhere); this returns false with the "unregistered" reason.
//   - not (Idempotent||PreCheck) → refuse: a re-drive after crash could double-fire.
//   - Class3+ and not (Reversible with an Inverse) → refuse: no containment without a defined, safe undo.
func canAutoRun(reg *ActionerRegistry, connectorKey, action string, risk RiskClass) (ok bool, reason string) {
	a, found := reg.lookup(connectorKey, action)
	if !found {
		return false, "no live actioner registered for " + connectorKey + ":" + action
	}
	if !a.Idempotent && !a.PreCheck {
		return false, "action not declared idempotent or pre-checking; requires human confirmation before a real effect"
	}
	if riskRank(risk) >= riskRank(RiskHigh) && (!a.Reversible || strings.TrimSpace(a.Inverse) == "") {
		return false, "high-risk containment must declare a reversible undo before it may auto-run"
	}
	return true, ""
}

// ActionExecution is the durable record of a connector step's two-phase execution (persisted in
// soar_action_execution). PriorState is captured in Phase B (MUST-3) so reverse only undoes real changes.
type ActionExecution struct {
	ID           uuid.UUID      `json:"id"`
	TenantID     uuid.UUID      `json:"tenant_id"`
	RunID        uuid.UUID      `json:"run_id"`
	StepIndex    int            `json:"step_index"`
	ActionKey    string         `json:"action_key"`
	ConnectorKey string         `json:"connector_key"`
	Target       string         `json:"target"`
	Status       string         `json:"status"` // executing | executed | failed | withheld
	Reason       string         `json:"reason"`
	ParamsHash   string         `json:"params_hash,omitempty"`
	PriorState   map[string]any `json:"prior_state,omitempty"`
	ConnectorRef string         `json:"connector_ref,omitempty"`
	DryRun       bool           `json:"dry_run"`
	Reversed     bool           `json:"reversed"`
}
