package detection

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists detection rules. Global rules (tenant_id NULL) are visible
// to all tenants via the RLS policy; tenants may add their own.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

func scanRules(rows pgx.Rows) ([]Rule, error) {
	var out []Rule
	for rows.Next() {
		var r Rule
		var cond []byte
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.Severity,
			&r.Confidence, &r.MITRE, &cond, &r.Expression, &r.Enabled, &r.CreatedAt,
			&r.Stage, &r.Version, &r.OwnerID, &r.SourceDependencies); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cond, &r.Condition)
		out = append(out, r)
	}
	return out, rows.Err()
}

const ruleCols = `id, tenant_id, name, description, severity, confidence, mitre, condition, expression, enabled, created_at, stage, version, owner_id, source_dependencies`

// activeStages are the lifecycle stages whose rules the engine evaluates (SRS §9.4): pilot, production,
// and tuned. draft/peer_review/qa/retired do not fire.
const activeStages = `('pilot','production','tuned')`

// ListActive returns enabled, lifecycle-active rules applicable to the tenant (global + own).
func (r *Repository) ListActive(ctx context.Context, tenantID uuid.UUID) ([]Rule, error) {
	var out []Rule
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM detection_rules WHERE enabled = true AND stage IN `+activeStages)
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanRules(rows)
		return err
	})
	return out, err
}

// List returns all rules visible to the tenant (management view).
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Rule, error) {
	var out []Rule
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM detection_rules ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanRules(rows)
		return err
	})
	return out, err
}

// Create inserts a tenant-owned rule.
func (r *Repository) Create(ctx context.Context, tenantID uuid.UUID, rule *Rule) error {
	cond, _ := json.Marshal(rule.Condition)
	if rule.MITRE == nil {
		rule.MITRE = []string{} // mitre is NOT NULL DEFAULT '{}'; never send SQL NULL
	}
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if rule.Stage == "" {
			rule.Stage = StageProduction
		}
		return tx.QueryRow(ctx,
			`INSERT INTO detection_rules (id, tenant_id, name, description, severity, confidence, mitre, condition, expression, enabled, stage)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at, version`,
			rule.ID, tenantID, rule.Name, rule.Description, rule.Severity, rule.Confidence, rule.MITRE, cond, rule.Expression, rule.Enabled, rule.Stage,
		).Scan(&rule.CreatedAt, &rule.Version)
	})
}

// SetEnabled toggles a tenant-owned rule.
func (r *Repository) SetEnabled(ctx context.Context, tenantID, id uuid.UUID, enabled bool) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE detection_rules SET enabled=$2 WHERE id=$1 AND tenant_id IS NOT NULL`, id, enabled)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}
