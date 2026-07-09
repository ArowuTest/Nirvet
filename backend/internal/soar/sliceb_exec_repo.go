package soar

// §6.11 slice B — durable two-phase execution persistence. A connector step's real effect cannot run in
// the run's DB tx, so its state lives here: Phase A CLAIMS (insert status='executing' under the
// UNIQUE(run_id,step_index) key — claim-once), Phase B calls the connector out-of-tx and captures observed
// prior_state, Phase C records the outcome. A crash between B and C leaves status='executing'; the reaper
// re-drives from Phase B (never re-runs Phase A), so the rate budget + intent audit happen exactly once.

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// getExecutionTx loads the durable execution row for a step (ok=false if none) within a tx.
func (r *Repository) getExecutionTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, stepIndex int) (*ActionExecution, bool, error) {
	var e ActionExecution
	var prior []byte
	err := tx.QueryRow(ctx,
		`SELECT id, run_id, step_index, action_key, connector_key, target, status, reason, prior_state,
		        connector_ref, dry_run, reversed
		   FROM soar_action_execution WHERE run_id=$1 AND step_index=$2`, runID, stepIndex).
		Scan(&e.ID, &e.RunID, &e.StepIndex, &e.ActionKey, &e.ConnectorKey, &e.Target, &e.Status, &e.Reason,
			&prior, &e.ConnectorRef, &e.DryRun, &e.Reversed)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(prior) > 0 {
		_ = json.Unmarshal(prior, &e.PriorState)
	}
	return &e, true, nil
}

// countClassExecutedLastHourTx counts rows of a risk class that had a REAL effect (executed) in the last
// hour — the per-class rate-limit meter (MUST rate cap). Uses the point-in-time risk_class ON the row
// (0063), never a catalog join, so a later re-classification cannot retro-change the count.
func (r *Repository) countClassExecutedLastHourTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, risk RiskClass) (int, error) {
	var n int
	err := tx.QueryRow(ctx,
		`SELECT count(*) FROM soar_action_execution
		  WHERE tenant_id=$1 AND risk_class=$2 AND status='executed' AND dry_run=false
		    AND claimed_at > now() - interval '1 hour'`, tenantID, string(risk)).Scan(&n)
	return n, err
}

// claimExecutionTx inserts the Phase-A claim under the idempotency key. Returns claimed=false (no error)
// when a row already exists for (run_id, step_index) — the claim happened once already, so the caller must
// resume rather than re-claim (no double budget/intent). Risk class is denormalized point-in-time.
func (r *Repository) claimExecutionTx(ctx context.Context, tx pgx.Tx, e *ActionExecution, risk RiskClass, dryRun bool) (claimed bool, err error) {
	tag, err := tx.Exec(ctx,
		`INSERT INTO soar_action_execution
		   (id, tenant_id, run_id, step_index, action_key, connector_key, target, risk_class, status, params_hash, dry_run)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'executing',$9,$10)
		 ON CONFLICT (run_id, step_index) DO NOTHING`,
		e.ID, e.TenantID, e.RunID, e.StepIndex, e.ActionKey, e.ConnectorKey, e.Target, string(risk),
		e.ParamsHash, dryRun)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// finishExecutionTx records Phase C: the outcome + observed prior state + connector ref. status is one of
// executed | failed. (withheld/dry-run are recorded via recordTerminalTx at claim time.)
func (r *Repository) finishExecutionTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, stepIndex int, status, connectorRef, reason string, priorState map[string]any) error {
	var prior []byte
	if priorState != nil {
		prior, _ = json.Marshal(priorState)
	}
	_, err := tx.Exec(ctx,
		`UPDATE soar_action_execution
		    SET status=$3, connector_ref=$4, reason=$5, prior_state=COALESCE($6, prior_state), updated_at=now()
		  WHERE run_id=$1 AND step_index=$2 AND status='executing'`,
		runID, stepIndex, status, connectorRef, reason, prior)
	return err
}

// recordTerminalTx inserts a directly-terminal execution row (withheld by the gate, or a dry-run) so a
// denial is durably recorded + surfaceable (MUST-4). Idempotent on the claim key.
func (r *Repository) recordTerminalTx(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, e *ActionExecution, risk RiskClass, status, reason string, dryRun bool) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO soar_action_execution
		   (id, tenant_id, run_id, step_index, action_key, connector_key, target, risk_class, status, reason, params_hash, dry_run)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 ON CONFLICT (run_id, step_index) DO NOTHING`,
		uuid.New(), tenantID, e.RunID, e.StepIndex, e.ActionKey, e.ConnectorKey, e.Target, string(risk),
		status, reason, e.ParamsHash, dryRun)
	return err
}

// markReversedTx flags an execution row reversed (MUST-3 reverse).
func (r *Repository) markReversedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE soar_action_execution SET reversed=true, updated_at=now() WHERE id=$1`, id)
	return err
}

// setCurrentStepTx advances a run's supervisor cursor (MUST-2: resume from the last non-terminal step).
func (r *Repository) setCurrentStepTx(ctx context.Context, tx pgx.Tx, runID uuid.UUID, step int) error {
	_, err := tx.Exec(ctx, `UPDATE playbook_runs SET current_step=$2 WHERE id=$1`, runID, step)
	return err
}
