package connector

import (
	"context"
	"encoding/json"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists connector configs (tenant-scoped, secrets encrypted).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// Create inserts a connector with an optional sealed secret and webhook key hash.
func (r *Repository) Create(ctx context.Context, c *ConnectorConfig, secret []byte, keyHash string) error {
	cfg, _ := json.Marshal(c.Config)
	return r.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO connector_configs (id, tenant_id, kind, name, direction, enabled, secret_ciphertext, key_hash, config)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING created_at`,
			c.ID, c.TenantID, c.Kind, c.Name, c.Direction, c.Enabled, secret, nullStr(keyHash), cfg,
		).Scan(&c.CreatedAt)
	})
}

// List returns connectors for a tenant (no secrets).
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]ConnectorConfig, error) {
	var out []ConnectorConfig
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, kind, name, direction, enabled, config, health, last_success, created_at
			   FROM connector_configs ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ConnectorConfig
			var cfg []byte
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Kind, &c.Name, &c.Direction, &c.Enabled,
				&cfg, &c.Health, &c.LastSuccess, &c.CreatedAt); err != nil {
				return err
			}
			_ = json.Unmarshal(cfg, &c.Config)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a connector.
func (r *Repository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM connector_configs WHERE id=$1`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// WebhookInfo is the minimal data needed to authenticate a webhook post.
type WebhookInfo struct {
	TenantID uuid.UUID
	KeyHash  string
	Enabled  bool
	Kind     string
}

// FindForWebhook looks up a connector by id across tenants (SECURITY DEFINER).
func (r *Repository) FindForWebhook(ctx context.Context, id uuid.UUID) (*WebhookInfo, error) {
	var wi WebhookInfo
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id, coalesce(key_hash,''), enabled, kind FROM connector_find_for_webhook($1)`, id,
		).Scan(&wi.TenantID, &wi.KeyHash, &wi.Enabled, &wi.Kind)
	})
	if err != nil {
		return nil, err
	}
	return &wi, nil
}

// MarkSuccess records a successful poll/receive.
func (r *Repository) MarkSuccess(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE connector_configs SET health='healthy', last_success=now() WHERE id=$1`, id)
		return err
	})
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// PullerConfig is an enabled pull connector for the poller (system-level view).
type PullerConfig struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Kind     string
	Secret   []byte // sealed client secret (decrypt via the vault)
	Config   map[string]any
}

// ListPullers enumerates enabled pull connectors across tenants (SECURITY DEFINER).
func (r *Repository) ListPullers(ctx context.Context) ([]PullerConfig, error) {
	var out []PullerConfig
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, kind, secret_ciphertext, config FROM connector_list_pullers()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pc PullerConfig
			var cfg []byte
			if err := rows.Scan(&pc.ID, &pc.TenantID, &pc.Kind, &pc.Secret, &cfg); err != nil {
				return err
			}
			_ = json.Unmarshal(cfg, &pc.Config)
			out = append(out, pc)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateCheckpoint stores the poll checkpoint + health for a connector (tenant-scoped).
func (r *Repository) UpdateCheckpoint(ctx context.Context, tenantID, id uuid.UUID, checkpoint, health string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE connector_configs
			    SET config = jsonb_set(config, '{checkpoint}', to_jsonb($2::text), true),
			        health = $3, last_success = now()
			  WHERE id = $1`,
			id, checkpoint, health)
		return err
	})
}
