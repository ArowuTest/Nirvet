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

// ActionExecutor performs one SOAR action for real. Implementations must be safe to call only after
// the engine has cleared authority-to-act + approval for the step. Kept as an interface so soar does
// not depend on notify/connector packages (consumer-defined, like incident's Notifier).
type ActionExecutor interface {
	Execute(ctx context.Context, tenantID uuid.UUID, action string, params map[string]any) (Outcome, error)
}

// Notifier enqueues a notification (implemented by notify.OutboxRepository). Narrow so soar does not
// import notify.
type Notifier interface {
	Enqueue(ctx context.Context, tenantID uuid.UUID, channel, recipient, subject, body string) error
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

// dispatch runs the catalog action and returns the step-result status + note. It never panics: an
// executor error is caught and recorded as failed (SOAR-009), so one bad step cannot abort the run.
func (e *Executors) dispatch(ctx context.Context, tenantID uuid.UUID, act ActionCatalog, params map[string]any) (status, note string) {
	if act.Executor == ExecutorManual {
		return StatusAwaitingCustomer, "manual action — awaiting customer/analyst: " + act.ActionKey
	}
	if ex, ok := e.byKey[act.ActionKey]; ok {
		out, err := ex.Execute(ctx, tenantID, act.ActionKey, params)
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

// --- notify executor (real, non-destructive) ---

// notifyExecutor enqueues a notification to the durable outbox — a real, safe effect proving the
// execution path works end-to-end (playbook step → outbox row → dispatcher delivery).
type notifyExecutor struct{ n Notifier }

// NewNotifyExecutor builds the notify action executor.
func NewNotifyExecutor(n Notifier) ActionExecutor { return &notifyExecutor{n: n} }

func (x *notifyExecutor) Execute(ctx context.Context, tenantID uuid.UUID, action string, params map[string]any) (Outcome, error) {
	subject := "SOAR action: " + action
	body := "SOAR playbook executed action " + action
	if inc, ok := params["incident_id"].(string); ok && inc != "" {
		body += " for incident " + inc
	}
	// Channel 'log' is always available and non-destructive; recipient resolution to the tenant
	// escalation matrix is a slice-B concern. The durable outbox + dispatcher deliver it for real.
	if err := x.n.Enqueue(ctx, tenantID, "log", "", subject, body); err != nil {
		return Outcome{}, err
	}
	return Outcome{Executed: true, Detail: "notification enqueued to outbox (" + action + ")"}, nil
}
