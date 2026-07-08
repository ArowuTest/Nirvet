package soar

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists playbooks and runs.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// TenantAuthority reads the tenant's authority-to-act mode (platform table).
func (r *Repository) TenantAuthority(ctx context.Context, tenantID uuid.UUID) (AuthorityMode, error) {
	var m string
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authority_mode FROM tenants WHERE id=$1`, tenantID).Scan(&m)
	})
	return AuthorityMode(m), err
}

// SetTenantAuthority updates a tenant's authority-to-act mode.
func (r *Repository) SetTenantAuthority(ctx context.Context, tenantID uuid.UUID, mode AuthorityMode) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenants SET authority_mode=$2 WHERE id=$1`, tenantID, string(mode))
		return err
	})
}

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

// CreateRun inserts a playbook run and its audit entry atomically (SOAR-006).
func (r *Repository) CreateRun(ctx context.Context, run *PlaybookRun, entry audit.Entry) error {
	steps, _ := json.Marshal(run.Steps)
	return r.db.WithTenant(ctx, run.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO playbook_runs (id, tenant_id, playbook_id, incident_id, status, steps_result, requested_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
			run.ID, run.TenantID, run.PlaybookID, run.IncidentID, run.Status, steps, run.RequestedBy,
		).Scan(&run.CreatedAt); err != nil {
			return err
		}
		return audit.Record(ctx, tx, entry)
	})
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

// UpdateRun persists status/steps/approval/completion and its audit entry atomically (SOAR-006).
func (r *Repository) UpdateRun(ctx context.Context, run *PlaybookRun, entry audit.Entry) error {
	steps, _ := json.Marshal(run.Steps)
	var completed any
	if run.CompletedAt != nil {
		completed = *run.CompletedAt
	}
	return r.db.WithTenant(ctx, run.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE playbook_runs SET status=$2, steps_result=$3, approved_by=$4, completed_at=$5 WHERE id=$1`,
			run.ID, run.Status, steps, run.ApprovedBy, completed); err != nil {
			return err
		}
		return audit.Record(ctx, tx, entry)
	})
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
