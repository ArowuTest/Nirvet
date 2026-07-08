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

// UpdateActive locks the active (open/promoted, in-window) cluster for the entity
// FOR UPDATE, applies mutate, and persists it in ONE transaction — so two alerts on the
// same cluster cannot lose an alert_count / risk update (R2 M-C). Returns (nil, nil)
// when no active cluster exists (the caller then creates one).
func (r *Repository) UpdateActive(ctx context.Context, tenantID uuid.UUID, entity string, since time.Time, mutate func(*Correlation)) (*Correlation, error) {
	var out *Correlation
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var c Correlation
		err := scanOne(tx.QueryRow(ctx,
			`SELECT id, tenant_id, entity, status, alert_count, max_severity, risk_score, techniques,
			        incident_id, first_seen, last_seen, created_at
			   FROM correlations
			  WHERE entity=$1 AND status IN ('open','promoted') AND last_seen >= $2
			  ORDER BY last_seen DESC LIMIT 1
			  FOR UPDATE`, entity, since), &c)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil // no active cluster; caller creates
			}
			return err
		}
		mutate(&c)
		ct, err := tx.Exec(ctx,
			`UPDATE correlations SET alert_count=$2, max_severity=$3, risk_score=$4, techniques=$5, last_seen=now()
			  WHERE id=$1`,
			c.ID, c.AlertCount, c.MaxSeverity, c.RiskScore, c.Techniques)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		out = &c
		return nil
	})
	return out, err
}

// ClaimForPromotion atomically transitions a cluster open->promoted, returning true
// only for the single caller that wins the transition (R2 H-C: exactly-once promotion —
// no duplicate incidents, no unbounded re-promotion). The incident is attached
// afterwards via SetIncident.
func (r *Repository) ClaimForPromotion(ctx context.Context, tenantID, id uuid.UUID) (bool, error) {
	claimed := false
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE correlations SET status='promoted' WHERE id=$1 AND status='open'`, id)
		if err != nil {
			return err
		}
		claimed = ct.RowsAffected() == 1
		return nil
	})
	return claimed, err
}

// SetIncident attaches the opened incident to a promoted cluster.
func (r *Repository) SetIncident(ctx context.Context, tenantID, id, incidentID uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE correlations SET incident_id=$2 WHERE id=$1`, id, incidentID)
		return err
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

// ListByEntity returns all correlation clusters for an entity (any status) — the
// entity-graph view (§6.9). Tenant-scoped via RLS.
func (r *Repository) ListByEntity(ctx context.Context, tenantID uuid.UUID, entity string) ([]Correlation, error) {
	var out []Correlation
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, entity, status, alert_count, max_severity, risk_score, techniques,
			        incident_id, first_seen, last_seen, created_at
			   FROM correlations WHERE entity=$1 ORDER BY last_seen DESC LIMIT 100`, entity)
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
