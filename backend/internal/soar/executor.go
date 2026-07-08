package soar

// Action execution seam (SRS §6.11 SOAR-002). The engine dispatches each permitted step through an
// ActionExecutor resolved from the action catalog. Real executors have a genuine effect (e.g. notify
// via the durable outbox); any action without a registered executor falls back to a TRUTHFUL
// simulation that names the connector.action it would invoke — so wiring a real EDR/IdP action later
// is a registration, not an engine change. The engine only reaches here AFTER authority-to-act +
// approval have permitted the step.

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Step result statuses recorded in a run's steps_result (widened from the original set).
const (
	StatusExecuted         = "executed"          // a real effect happened
	StatusSimulated        = "simulated"         // no live executor — recorded, no effect
	StatusFailed           = "failed"            // executor attempted and errored (SOAR-009)
	StatusAwaitingApproval = "awaiting_approval" // gated, pending human approval
	StatusAwaitingCustomer = "awaiting_customer" // manual action — customer/analyst must act
	StatusSkipped          = "skipped"           // rejected or not run
)

// Outcome is what an ActionExecutor reports back.
type Outcome struct {
	Executed bool   // true = a real effect occurred; false = the executor chose to simulate
	Detail   string // human-readable note recorded on the step
}

// ActionExecutor performs one SOAR action for real. It runs INSIDE the run's transaction (tx) so its
// effect + audit + the run-state change commit together (Round-4 M2: effect and audit can never
// diverge). Implementations must be safe to call only after the engine has cleared authority-to-act +
// approval for the step. Kept as an interface so soar does not depend on notify/connector packages.
type ActionExecutor interface {
	Execute(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action string, params map[string]any) (Outcome, error)
}

// Notifier enqueues a notification within the caller's transaction (implemented by
// notify.OutboxRepository.EnqueueTx). Narrow so soar does not import notify.
type Notifier interface {
	EnqueueTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, channel, recipient, subject, body string) error
}

// Executors is the registry mapping action_key -> executor. Unregistered actions fall back to a
// truthful simulation. Safe for concurrent read after construction (built once at wiring time).
type Executors struct{ byKey map[string]ActionExecutor }

// NewExecutors builds an empty registry.
func NewExecutors() *Executors { return &Executors{byKey: map[string]ActionExecutor{}} }

// Register binds an action_key to a real executor (chainable).
func (e *Executors) Register(actionKey string, ex ActionExecutor) *Executors {
	e.byKey[actionKey] = ex
	return e
}

// dispatch runs the catalog action within tx and returns the step-result status + note. It never
// aborts the run: a returned error is recorded as failed, and a PANIC in a (future connector)
// executor is recovered per-step (Round-4 M4) and recorded as failed — so one bad step cannot crash
// the loop or leave the run without a record (SOAR-009). Runs inside the run's tx (M2).
func (e *Executors) dispatch(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, act ActionCatalog, params map[string]any) (status, note string) {
	if act.Executor == ExecutorManual {
		return StatusAwaitingCustomer, "manual action — awaiting customer/analyst: " + act.ActionKey
	}
	if ex, ok := e.byKey[act.ActionKey]; ok {
		out, err := safeExecute(ctx, tx, tenantID, act.ActionKey, params, ex)
		if err != nil {
			return StatusFailed, "execution failed: " + err.Error()
		}
		if out.Executed {
			return StatusExecuted, out.Detail
		}
		return StatusSimulated, out.Detail
	}
	// No live executor for this action → honest simulation naming what it would invoke.
	target := act.ConnectorKey
	if target == "" {
		target = string(act.Executor)
	}
	return StatusSimulated, fmt.Sprintf("simulated: would invoke %s.%s (no live executor configured)", target, act.ActionKey)
}

// safeExecute runs an executor with per-step panic recovery (Round-4 M4): a panic becomes an error,
// so the dispatch loop records the step failed and continues rather than unwinding mid-run.
func safeExecute(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action string, params map[string]any, ex ActionExecutor) (out Outcome, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("executor panic: %v", r)
		}
	}()
	return ex.Execute(ctx, tx, tenantID, action, params)
}

// --- notify executor (real, non-destructive) ---

// notifyExecutor enqueues a notification to the durable outbox — a real, safe effect proving the
// execution path works end-to-end (playbook step → outbox row → dispatcher delivery).
type notifyExecutor struct{ n Notifier }

// NewNotifyExecutor builds the notify action executor.
func NewNotifyExecutor(n Notifier) ActionExecutor { return &notifyExecutor{n: n} }

func (x *notifyExecutor) Execute(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action string, params map[string]any) (Outcome, error) {
	subject := "SOAR action: " + action
	body := "SOAR playbook executed action " + action
	if inc, ok := params["incident_id"].(string); ok && inc != "" {
		body += " for incident " + inc
	}
	// Channel 'log' is always available and non-destructive; recipient resolution to the tenant
	// escalation matrix is a slice-B concern. Enqueued within the run's tx so the notification and
	// the run record commit atomically (M2); the dispatcher delivers it for real.
	if err := x.n.EnqueueTx(ctx, tx, tenantID, "log", "", subject, body); err != nil {
		return Outcome{}, err
	}
	return Outcome{Executed: true, Detail: "notification enqueued to outbox (" + action + ")"}, nil
}
