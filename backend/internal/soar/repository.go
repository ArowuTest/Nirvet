package soar

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists playbooks and runs.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// ListPlaybooks returns global + tenant playbooks.
func (r *Repository) ListPlaybooks(ctx context.Context, tenantID uuid.UUID) ([]Playbook, error) {
	var out []Playbook
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, name, description, trigger_category, steps, enabled, created_at
			   FROM playbooks WHERE enabled = true ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPlaybook(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// GetPlaybook returns one playbook (global or tenant).
func (r *Repository) GetPlaybook(ctx context.Context, tenantID, id uuid.UUID) (*Playbook, error) {
	var p Playbook
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT id, tenant_id, name, description, trigger_category, steps, enabled, created_at
			   FROM playbooks WHERE id=$1`, id)
		var e error
		p, e = scanPlaybook(row)
		return e
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// RunTx executes fn inside the tenant's transaction — the seam that lets Run/Approve dispatch
// executors, persist the run, and write audit all in ONE tx (Round-4 M2: effect + audit + state
// commit together, or none do).
func (r *Repository) RunTx(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return r.db.WithTenant(ctx, tenantID, fn)
}

// insertRunTx inserts a playbook run within an existing tx.
func (r *Repository) insertRunTx(ctx context.Context, tx pgx.Tx, run *PlaybookRun) error {
	steps, _ := json.Marshal(run.Steps)
	return tx.QueryRow(ctx,
		`INSERT INTO playbook_runs (id, tenant_id, playbook_id, incident_id, status, steps_result, requested_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
		run.ID, run.TenantID, run.PlaybookID, run.IncidentID, run.Status, steps, run.RequestedBy,
	).Scan(&run.CreatedAt)
}

// updateRunTx persists status/steps/approval/completion within an existing tx.
func (r *Repository) updateRunTx(ctx context.Context, tx pgx.Tx, run *PlaybookRun) error {
	steps, _ := json.Marshal(run.Steps)
	var completed any
	if run.CompletedAt != nil {
		completed = *run.CompletedAt
	}
	_, err := tx.Exec(ctx,
		`UPDATE playbook_runs SET status=$2, steps_result=$3, approved_by=$4, completed_at=$5 WHERE id=$1`,
		run.ID, run.Status, steps, run.ApprovedBy, completed)
	return err
}

// lockRunKeyTx takes a transaction-scoped advisory lock keyed on (playbook, incident) so concurrent
// Runs for the same pair serialise (Round-4 R-1): the fully-auto path writes a TERMINAL row that the
// active-status partial unique index (0038) does not cover, so without this two truly-concurrent
// auto-runs could both pass the idempotency check and double-dispatch. Held until the tx ends.
func (r *Repository) lockRunKeyTx(ctx context.Context, tx pgx.Tx, playbookID, incidentID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		playbookID.String()+":"+incidentID.String())
	return err
}

// claimPendingTx atomically moves a run pending_approval→running so exactly ONE approver can proceed
// (Round-4 R-2 claim-then-act). The row lock serialises concurrent approves; the loser matches 0 rows.
func (r *Repository) claimPendingTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	ct, err := tx.Exec(ctx, `UPDATE playbook_runs SET status='running' WHERE id=$1 AND status='pending_approval'`, id)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}

// activeRunForTx returns an existing run for (playbook, incident) within tx, for idempotency: a
// retried/double-submitted Run must not re-dispatch. It matches a still-active run OR ANY run created
// within a short idempotency window — the latter covers the FULLY-AUTO path (Round-4 R-1), where a run
// is written directly as terminal 'completed'/'failed' and so is never caught by the active-status
// filter or the 0038 partial index. Only meaningful for incident-linked runs; ad-hoc runs aren't deduped.
func (r *Repository) activeRunForTx(ctx context.Context, tx pgx.Tx, tenantID, playbookID uuid.UUID, incidentID *uuid.UUID) (*PlaybookRun, error) {
	if incidentID == nil {
		return nil, nil
	}
	var run PlaybookRun
	var steps []byte
	err := tx.QueryRow(ctx,
		`SELECT id, tenant_id, playbook_id, incident_id, status, steps_result, requested_by, approved_by, created_at, completed_at
		   FROM playbook_runs
		  WHERE playbook_id=$1 AND incident_id=$2
		    AND (status IN ('pending_approval','running') OR created_at > now() - interval '60 seconds')
		  ORDER BY created_at DESC LIMIT 1`, playbookID, *incidentID).
		Scan(&run.ID, &run.TenantID, &run.PlaybookID, &run.IncidentID, &run.Status, &steps,
			&run.RequestedBy, &run.ApprovedBy, &run.CreatedAt, &run.CompletedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(steps, &run.Steps)
	return &run, nil
}

// GetRun returns a run.
func (r *Repository) GetRun(ctx context.Context, tenantID, id uuid.UUID) (*PlaybookRun, error) {
	var run PlaybookRun
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var steps []byte
		e := tx.QueryRow(ctx,
			`SELECT id, tenant_id, playbook_id, incident_id, status, steps_result, requested_by, approved_by, created_at, completed_at
			   FROM playbook_runs WHERE id=$1`, id,
		).Scan(&run.ID, &run.TenantID, &run.PlaybookID, &run.IncidentID, &run.Status, &steps,
			&run.RequestedBy, &run.ApprovedBy, &run.CreatedAt, &run.CompletedAt)
		if e != nil {
			return e
		}
		_ = json.Unmarshal(steps, &run.Steps)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// ListRuns returns recent runs.
func (r *Repository) ListRuns(ctx context.Context, tenantID uuid.UUID) ([]PlaybookRun, error) {
	var out []PlaybookRun
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, playbook_id, incident_id, status, steps_result, requested_by, approved_by, created_at, completed_at
			   FROM playbook_runs ORDER BY created_at DESC LIMIT 100`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var run PlaybookRun
			var steps []byte
			if err := rows.Scan(&run.ID, &run.TenantID, &run.PlaybookID, &run.IncidentID, &run.Status,
				&steps, &run.RequestedBy, &run.ApprovedBy, &run.CreatedAt, &run.CompletedAt); err != nil {
				return err
			}
			_ = json.Unmarshal(steps, &run.Steps)
			out = append(out, run)
		}
		return rows.Err()
	})
	return out, err
}

func scanPlaybook(row pgx.Row) (Playbook, error) {
	var p Playbook
	var steps []byte
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.TriggerCategory, &steps, &p.Enabled, &p.CreatedAt); err != nil {
		return p, err
	}
	_ = json.Unmarshal(steps, &p.Steps)
	return p, nil
}
