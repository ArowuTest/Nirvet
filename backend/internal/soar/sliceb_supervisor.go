package soar

// §6.11 slice B — the two-phase supervisor engine (MUST-2). It drives ONE permitted connector step
// through the destructive gate and the durable two-phase model. Authority-to-act + four-eyes are
// enforced by the caller (Run/Approve) before handoff; the supervisor enforces the destructive-action
// gate (kill-switch / enablement / dry-run / rate) and the crash-safe two-phase mechanics:
//
//	Phase A (tx1): gate → if withhold/manual, record terminal + audit the DENIAL (MUST-4) and stop;
//	               else CLAIM (claim-once via the unique key) + intent + credential-decrypt audit.
//	Phase B (no tx): RE-READ the kill-switch (emergency stop for a claimed-but-unexecuted step);
//	               decrypt vault creds; call the Actioner; capture OBSERVED prior_state (MUST-3).
//	Phase C (tx2): record the outcome + prior_state + outcome audit.
//
// Crash-safe: everything keys on the durable soar_action_execution row. A crash between B and C leaves
// status='executing'; a re-drive resumes at Phase B and NEVER re-runs Phase A, so the rate budget and
// the intent audit happen exactly once (the Actioner is idempotent-or-precheck by the MUST-1 contract).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// StatusWithheld is a step blocked by the destructive gate (recorded + surfaced, no effect).
const StatusWithheld = "withheld"

// CredDecryptor returns a tenant's vault-decrypted connector credentials for the Phase-B external call.
type CredDecryptor interface {
	ConnectorCreds(ctx context.Context, tenantID uuid.UUID, connectorKey string) ([]byte, error)
}

// Supervisor executes connector steps two-phase. Built once at wiring; safe for concurrent use.
type Supervisor struct {
	repo      *Repository
	actioners *ActionerRegistry
	creds     CredDecryptor
	log       *slog.Logger
	alerter   ContainmentAlerter // optional; surfaces a failed/stalled containment (reconciler D-3)
}

// NewSupervisor builds the engine. A nil actioner registry means "no real containment wired" (every
// connector step simulates elsewhere); a nil creds decryptor means creds are not passed to the Actioner.
func NewSupervisor(repo *Repository, actioners *ActionerRegistry, creds CredDecryptor, log *slog.Logger) *Supervisor {
	if actioners == nil {
		actioners = NewActionerRegistry()
	}
	return &Supervisor{repo: repo, actioners: actioners, creds: creds, log: log}
}

// ExecuteConnectorStep drives one permitted connector step. Idempotent + crash-resumable: an already
// terminal step is reflected; an 'executing' step resumes at Phase B; a fresh step runs Phase A→B→C.
// Returns the step-level status (executed|simulated|withheld|awaiting_customer|failed) + a note.
func (s *Supervisor) ExecuteConnectorStep(ctx context.Context, tenantID uuid.UUID, actor auth.Principal, runID uuid.UUID, stepIndex int, act ActionCatalog, target string, params map[string]any) (status, note string, err error) {
	// Reflect a durable prior outcome (idempotent replay / resume).
	var existing *ActionExecution
	if err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ex, ok, e := s.repo.getExecutionTx(ctx, tx, runID, stepIndex)
		if ok {
			existing = ex
		}
		return e
	}); err != nil {
		return "", "", err
	}
	if existing != nil {
		switch existing.Status {
		case StatusExecuted:
			if existing.DryRun {
				return StatusSimulated, "dry-run (already recorded)", nil
			}
			return StatusExecuted, "already executed: " + existing.ConnectorRef, nil
		case StatusFailed:
			return StatusFailed, "already failed: " + existing.Reason, nil
		case StatusWithheld:
			return StatusWithheld, existing.Reason, nil
		case "executing":
			return s.phaseBC(ctx, tenantID, actor, existing, act, target, params)
		}
	}

	// Phase A: read config, evaluate the gate, and either record a terminal denial or claim.
	plat, e := s.repo.GetPlatformFlags(ctx)
	if e != nil {
		return "", "", e
	}
	set, e := s.repo.GetSoarSettings(ctx, tenantID)
	if e != nil {
		return "", "", e
	}
	canAuto, reason := canAutoRun(s.actioners, act.ConnectorKey, act.ActionKey, act.RiskClass)

	ex := &ActionExecution{
		ID: uuid.New(), TenantID: tenantID, RunID: runID, StepIndex: stepIndex,
		ActionKey: act.ActionKey, ConnectorKey: act.ConnectorKey, Target: target, ParamsHash: hashParams(params),
	}
	var outcome gateOutcome
	var gateReason string
	claimed := false
	if err := s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		n, e := s.repo.countClassExecutedLastHourTx(ctx, tx, tenantID, act.RiskClass)
		if e != nil {
			return e
		}
		outcome, gateReason = evaluateGate(gateInputs{
			killSwitch: plat.KillSwitch, platformDryRun: plat.DryRun,
			tenantEnabled: set.DestructiveEnabled, tenantDryRun: set.DryRun,
			canAuto: canAuto, canAutoReason: reason, rateRemaining: set.rateCapFor(act.RiskClass) - n,
		})
		switch outcome {
		case gateWithhold, gateManual:
			decision := "withheld"
			if outcome == gateManual {
				decision = "manual_required"
			}
			if e := s.repo.recordTerminalTx(ctx, tx, tenantID, ex, act.RiskClass, StatusWithheld, gateReason, false); e != nil {
				return e
			}
			return audit.Record(ctx, tx, denyEntry(actor, act, target, decision, gateReason))
		default: // gateLive / gateDryRun → claim exactly once, audit intent + credential-decrypt.
			ok, e := s.repo.claimExecutionTx(ctx, tx, ex, act.RiskClass, outcome == gateDryRun)
			if e != nil {
				return e
			}
			if !ok {
				return nil // raced by another driver; resume on the next pass
			}
			claimed = true
			if e := audit.Record(ctx, tx, intentEntry(actor, act, target, outcome)); e != nil {
				return e
			}
			return audit.Record(ctx, tx, credDecryptEntry(actor, act))
		}
	}); err != nil {
		return "", "", err
	}

	switch outcome {
	case gateWithhold:
		return StatusWithheld, gateReason, nil
	case gateManual:
		return StatusAwaitingCustomer, gateReason, nil
	}
	if !claimed {
		return "", "", nil // a concurrent claim owns it; caller re-drives
	}
	ex.DryRun = outcome == gateDryRun
	return s.phaseBC(ctx, tenantID, actor, ex, act, target, params)
}

// phaseBC runs Phase B (out of tx: kill-switch re-read, decrypt, connector call, capture prior_state)
// then Phase C (tx2: outcome + audit). Safe to call on a freshly-claimed row OR to resume an 'executing'
// row after a crash — it never re-claims, so the budget/intent audit stay exactly-once.
func (s *Supervisor) phaseBC(ctx context.Context, tenantID uuid.UUID, actor auth.Principal, ex *ActionExecution, act ActionCatalog, target string, params map[string]any) (status, note string, err error) {
	// Phase-B kill-switch re-read: an emergency stop must abort a claimed-but-unexecuted step.
	if !ex.DryRun {
		if plat, e := s.repo.GetPlatformFlags(ctx); e == nil && plat.KillSwitch {
			s.finish(ctx, tenantID, ex, StatusFailed, "", "aborted: kill-switch engaged after claim", nil,
				denyEntry(actor, act, target, "killed_mid_flight", "kill-switch engaged after claim"))
			return StatusFailed, "aborted: kill-switch engaged after claim", nil
		}
	}

	// Dry-run: full gate ran, no real effect.
	if ex.DryRun {
		s.finish(ctx, tenantID, ex, StatusExecuted, "dry-run", "dry-run: no real effect", nil,
			outcomeEntry(actor, act, target, "dry_run", "dry-run"))
		return StatusSimulated, "dry-run: no real effect (gate passed)", nil
	}

	a, ok := s.actioners.lookup(act.ConnectorKey, act.ActionKey)
	if !ok {
		s.finish(ctx, tenantID, ex, StatusFailed, "", "no actioner registered", nil,
			outcomeEntry(actor, act, target, "failed", "no actioner"))
		return StatusFailed, "no actioner registered", nil
	}
	var creds []byte
	if s.creds != nil {
		c, e := s.creds.ConnectorCreds(ctx, tenantID, act.ConnectorKey)
		if e != nil {
			s.finish(ctx, tenantID, ex, StatusFailed, "", "credential decrypt failed", nil,
				outcomeEntry(actor, act, target, "failed", "credential decrypt failed"))
			return StatusFailed, "credential decrypt failed", nil
		}
		creds = c
	}
	// H-1 (round #34): a destructive PreCheck Actioner must attribute reversibility by CORRELATION, not by
	// "is this a resume". The engine injects a STABLE per-step correlator (run_id:step_index — identical on
	// the first attempt and any crash-resume) into params; the Actioner embeds it in the external action's
	// audit/comment on execute, and on a PreCheck that finds an already-active action returns
	// prior_state.changed=true ONLY if that action carries THIS correlator (our own, must stay reversible)
	// and false otherwise (a foreign pre-existing effect we must never reverse — MUST-3). The `resumed`
	// proxy was insufficient: a claim proves we CLAIMED (Phase A), not that we POSTed (Phase B), so a crash
	// between a fresh no-op and commit would fail OPEN (release a machine a foreign actor isolated).
	callParams := make(map[string]any, len(params)+1)
	for k, v := range params {
		callParams[k] = v
	}
	callParams[ActionCorrelatorParam] = ex.RunID.String() + ":" + strconv.Itoa(ex.StepIndex)

	ref, prior, callErr := safeCall(ctx, a, creds, target, callParams)
	if callErr != nil {
		s.finish(ctx, tenantID, ex, StatusFailed, "", "execution failed: "+callErr.Error(), prior,
			outcomeEntry(actor, act, target, "failed", callErr.Error()))
		return StatusFailed, "execution failed: " + callErr.Error(), nil
	}
	s.finish(ctx, tenantID, ex, StatusExecuted, ref, "", prior,
		outcomeEntry(actor, act, target, "executed", ref))
	return StatusExecuted, "executed: " + ref, nil
}

// finish records Phase C (outcome + prior_state) and its audit in one tx (best-effort).
func (s *Supervisor) finish(ctx context.Context, tenantID uuid.UUID, ex *ActionExecution, rowStatus, connRef, reason string, prior map[string]any, auditEntry audit.Entry) {
	_ = s.repo.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if e := s.repo.finishExecutionTx(ctx, tx, ex.RunID, ex.StepIndex, rowStatus, connRef, reason, prior); e != nil {
			return e
		}
		return audit.Record(ctx, tx, auditEntry)
	})
}

// safeCall runs an Actioner with panic recovery (a panic becomes an error → the step records failed).
func safeCall(ctx context.Context, a Actioner, creds []byte, target string, params map[string]any) (ref string, prior map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("actioner panic: %v", r)
		}
	}()
	return a.Fn(ctx, creds, target, params)
}

func hashParams(params map[string]any) string {
	b, _ := json.Marshal(params)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// --- audit entry builders (target identity legible; secret params only as a hash) ---

func intentEntry(actor auth.Principal, act ActionCatalog, target string, o gateOutcome) audit.Entry {
	mode := "live"
	if o == gateDryRun {
		mode = "dry_run"
	}
	return audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email, Action: "soar.action_intent",
		Target: "action:" + act.ActionKey, Metadata: map[string]any{"connector": act.ConnectorKey, "target": target, "risk": act.RiskClass, "mode": mode}}
}

func credDecryptEntry(actor auth.Principal, act ActionCatalog) audit.Entry {
	return audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email, Action: "soar.credential_decrypt",
		Target: "connector:" + act.ConnectorKey, Metadata: map[string]any{"action": act.ActionKey}}
}

func outcomeEntry(actor auth.Principal, act ActionCatalog, target, result, detail string) audit.Entry {
	return audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email, Action: "soar.action_outcome",
		Target: "action:" + act.ActionKey, Metadata: map[string]any{"connector": act.ConnectorKey, "target": target, "result": result, "detail": detail}}
}

func denyEntry(actor auth.Principal, act ActionCatalog, target, decision, reason string) audit.Entry {
	return audit.Entry{ActorID: actor.UserID, ActorEmail: actor.Email, Action: "soar.action_denied",
		Target: "action:" + act.ActionKey, Metadata: map[string]any{"connector": act.ConnectorKey, "target": target, "risk": act.RiskClass, "decision": decision, "reason": reason}}
}
