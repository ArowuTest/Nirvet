package soar

// §6.11 completion reconciler (D-3) — persistence. Turns a submitted containment's `executed` (accepted by
// the vendor) into `confirmed` (the vendor reports it took effect), or flips it to `failed` when the vendor
// reports the action did NOT take hold. Only rows WE caused are considered (prior_state.changed=true — G-2),
// and the poll key is the BARE vendor action id from prior_state.action_id (G-1), never the display connector_ref.

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// unconfirmedExecution is one executed-but-unconfirmed connector action we caused, ready to poll.
type unconfirmedExecution struct {
	TenantID     uuid.UUID
	ID           uuid.UUID
	ActionKey    string
	ConnectorKey string
	ActionID     string // bare vendor machineAction id (prior_state.action_id, G-1)
	AgeSecs      int    // seconds since claim (DB clock), for the stall check
}

// unconfirmedExecutions lists connector actions awaiting confirmation, at the SYSTEM level (spans tenants)
// via the SECURITY DEFINER soar_unconfirmed_executions function. G-2 (only rows we caused) + the grace window
// are enforced inside the function.
func (r *Repository) unconfirmedExecutions(ctx context.Context, graceSecs int) ([]unconfirmedExecution, error) {
	var out []unconfirmedExecution
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT tenant_id, id, action_key, connector_key, action_id, age_secs FROM soar_unconfirmed_executions($1)`, graceSecs)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var u unconfirmedExecution
			if e := rows.Scan(&u.TenantID, &u.ID, &u.ActionKey, &u.ConnectorKey, &u.ActionID, &u.AgeSecs); e != nil {
				return e
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// markConfirmed records that the vendor confirmed the action took effect (terminal Succeeded, or a
// synchronous action with no async confirmation). Idempotent + tenant-scoped.
func (r *Repository) markConfirmed(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE soar_action_execution SET confirmed=true, confirmation_status=$2, confirmed_at=now()
			  WHERE id=$1 AND NOT confirmed`, id, status)
		return err
	})
}

// markContainmentFailed records that the vendor reported the action FAILED to take effect: the row flips
// executed→failed with the terminal status. Because listReversibleExecutions selects only status='executed'
// rows, a failed containment is thereby EXCLUDED from reverse (there is nothing to undo). Guarded on
// status='executed' so it is idempotent. Tenant-scoped.
func (r *Repository) markContainmentFailed(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE soar_action_execution SET status='failed', confirmation_status=$2, confirmed_at=now()
			  WHERE id=$1 AND status='executed'`, id, status)
		return err
	})
}
