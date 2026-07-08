package correlation

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists correlations (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// FindOpen returns the open correlation for an entity whose last_seen is within
// the window, or (nil, nil) if none — the caller then creates a new cluster.
func (r *Repository) FindOpen(ctx context.Context, tenantID uuid.UUID, entity string, since time.Time) (*Correlation, error) {
	var c Correlation
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return scanOne(tx.QueryRow(ctx,
			`SELECT id, tenant_id, entity, status, alert_count, max_severity, risk_score, techniques,
			        incident_id, first_seen, last_seen, created_at
			   FROM correlations
			  WHERE entity=$1 AND status='open' AND last_seen >= $2
			  ORDER BY last_seen DESC LIMIT 1`, entity, since), &c)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}

// Create inserts a new correlation.
func (r *Repository) Create(ctx context.Context, c *Correlation) error {
	return r.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO correlations (id, tenant_id, entity, status, alert_count, max_severity, risk_score, techniques)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING first_seen, last_seen, created_at`,
			c.ID, c.TenantID, c.Entity, c.Status, c.AlertCount, c.MaxSeverity, c.RiskScore, c.Techniques,
		).Scan(&c.FirstSeen, &c.LastSeen, &c.CreatedAt)
	})
}

// Update persists a cluster's recomputed aggregate.
func (r *Repository) Update(ctx context.Context, c *Correlation) error {
	return r.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE correlations
			    SET alert_count=$2, max_severity=$3, risk_score=$4, techniques=$5,
			        status=$6, incident_id=$7, last_seen=now()
			  WHERE id=$1`,
			c.ID, c.AlertCount, c.MaxSeverity, c.RiskScore, c.Techniques, c.Status, c.IncidentID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// List returns a tenant's correlations, highest risk first.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, status string) ([]Correlation, error) {
	var out []Correlation
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, entity, status, alert_count, max_severity, risk_score, techniques,
			        incident_id, first_seen, last_seen, created_at
			   FROM correlations
			  WHERE ($1='' OR status=$1)
			  ORDER BY risk_score DESC, last_seen DESC LIMIT 200`, status)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Correlation
			if err := scanRow(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one correlation.
func (r *Repository) Get(ctx context.Context, tenantID, id uuid.UUID) (*Correlation, error) {
	var c Correlation
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return scanOne(tx.QueryRow(ctx,
			`SELECT id, tenant_id, entity, status, alert_count, max_severity, risk_score, techniques,
			        incident_id, first_seen, last_seen, created_at
			   FROM correlations WHERE id=$1`, id), &c)
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

type scanner interface{ Scan(dest ...any) error }

func scanOne(row scanner, c *Correlation) error {
	return row.Scan(&c.ID, &c.TenantID, &c.Entity, &c.Status, &c.AlertCount, &c.MaxSeverity,
		&c.RiskScore, &c.Techniques, &c.IncidentID, &c.FirstSeen, &c.LastSeen, &c.CreatedAt)
}

func scanRow(rows pgx.Rows, c *Correlation) error { return scanOne(rows, c) }
