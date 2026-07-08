package alert

import (
	"context"
	"errors"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists alerts (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

const alertCols = `id, tenant_id, event_id, detection_id, dedupe_key, title, severity, confidence,
	source, status, assignee_id, actor_ref, target_ref, mitre, incident_id, created_at`

func scanAlert(row pgx.Row, a *Alert) error {
	return row.Scan(&a.ID, &a.TenantID, &a.EventID, &a.DetectionID, &a.DedupeKey, &a.Title,
		&a.Severity, &a.Confidence, &a.Source, &a.Status, &a.AssigneeID, &a.ActorRef,
		&a.TargetRef, &a.MITRE, &a.IncidentID, &a.CreatedAt)
}

// Create inserts an alert idempotently on (tenant_id, dedupe_key). Returns true
// if a new alert was created (false = an alert for this (event, rule) exists).
func (r *Repository) Create(ctx context.Context, a *Alert) (bool, error) {
	if a.MITRE == nil {
		a.MITRE = []string{} // column is NOT NULL DEFAULT '{}'; never send SQL NULL
	}
	inserted := false
	err := r.db.WithTenant(ctx, a.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`INSERT INTO alerts
			  (id, tenant_id, event_id, detection_id, dedupe_key, title, severity, confidence, source, status, actor_ref, target_ref, mitre)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			 ON CONFLICT (tenant_id, dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING
			 RETURNING created_at`,
			a.ID, a.TenantID, a.EventID, a.DetectionID, a.DedupeKey, a.Title, a.Severity,
			a.Confidence, a.Source, a.Status, a.ActorRef, a.TargetRef, a.MITRE,
		).Scan(&a.CreatedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil // duplicate — not inserted
		}
		if e != nil {
			return e
		}
		inserted = true
		return nil
	})
	return inserted, err
}

// List returns alerts for a tenant, optionally filtered by status.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, status string, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []Alert
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+alertCols+` FROM alerts
			  WHERE ($1 = '' OR status = $1)
			  ORDER BY created_at DESC LIMIT $2`, status, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Alert
			if err := scanAlert(rows, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one alert.
func (r *Repository) Get(ctx context.Context, tenantID, id uuid.UUID) (*Alert, error) {
	var a Alert
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return scanAlert(tx.QueryRow(ctx, `SELECT `+alertCols+` FROM alerts WHERE id=$1`, id), &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Assign sets the assignee and marks the alert assigned.
func (r *Repository) Assign(ctx context.Context, tenantID, id, assignee uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE alerts SET assignee_id=$2, status='assigned' WHERE id=$1 AND status IN ('new','assigned')`, id, assignee)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// MarkPromoted links the alert to an incident.
// SetCorrelation links an alert to its correlation cluster and records its
// individual risk score (SRS §6.7). A nil correlationID clears the link.
func (r *Repository) SetCorrelation(ctx context.Context, tenantID, id uuid.UUID, correlationID *uuid.UUID, risk int) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE alerts SET correlation_id=$2, risk_score=$3 WHERE id=$1`, id, correlationID, risk)
		return err
	})
}

func (r *Repository) MarkPromoted(ctx context.Context, tx pgx.Tx, id, incidentID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE alerts SET status='promoted', incident_id=$2 WHERE id=$1`, id, incidentID)
	return err
}
