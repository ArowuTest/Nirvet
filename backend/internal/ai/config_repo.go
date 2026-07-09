package ai

// §6.12 #117 A-4 — config-surface writes. Global provider + allowlist + tenant policy are platform-admin (system
// context); the tenant provider override is tenant-scoped (RLS). Single-row-per-scope upsert (UPDATE else INSERT).

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProviderInput is a validated, ready-to-store provider row. APIKeyRef is the base64 sealed ciphertext ("" = none).
type ProviderInput struct {
	Kind      ProviderKind
	BaseURL   string
	Model     string
	APIKeyRef string
}

// AllowedEndpoint is a platform-admin trust-list entry.
type AllowedEndpoint struct {
	ID     uuid.UUID `json:"id"`
	Scheme string    `json:"scheme"`
	Host   string    `json:"host"`
	Port   int       `json:"port"`
	Note   string    `json:"note"`
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// SetGlobalProvider upserts the single global (tenant_id NULL) provider row. Platform-admin, system context.
func (r *Repository) SetGlobalProvider(ctx context.Context, in ProviderInput) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return upsertProvider(ctx, tx, nil, in)
	})
}

// SetTenantProvider upserts a tenant's provider override (RLS own-scope).
func (r *Repository) SetTenantProvider(ctx context.Context, tenantID uuid.UUID, in ProviderInput) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return upsertProvider(ctx, tx, &tenantID, in)
	})
}

func upsertProvider(ctx context.Context, tx pgx.Tx, tenantID *uuid.UUID, in ProviderInput) error {
	var tag interface{ RowsAffected() int64 }
	var err error
	if tenantID == nil {
		tag, err = tx.Exec(ctx, `UPDATE ai_provider SET provider_kind=$1, base_url=$2, model=$3, api_key_ref=$4, updated_at=now()
			WHERE tenant_id IS NULL`, string(in.Kind), strOrNil(in.BaseURL), in.Model, strOrNil(in.APIKeyRef))
	} else {
		tag, err = tx.Exec(ctx, `UPDATE ai_provider SET provider_kind=$1, base_url=$2, model=$3, api_key_ref=$4, updated_at=now()
			WHERE tenant_id=$5`, string(in.Kind), strOrNil(in.BaseURL), in.Model, strOrNil(in.APIKeyRef), *tenantID)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO ai_provider (tenant_id, provider_kind, base_url, model, api_key_ref)
		VALUES ($1,$2,$3,$4,$5)`, tenantID, string(in.Kind), strOrNil(in.BaseURL), in.Model, strOrNil(in.APIKeyRef))
	return err
}

// ProviderView is a redacted read of the effective/own provider row (never returns the key).
type ProviderView struct {
	Kind    ProviderKind `json:"kind"`
	BaseURL string       `json:"base_url,omitempty"`
	Model   string       `json:"model"`
	HasKey  bool         `json:"has_key"`
	Global  bool         `json:"global"` // true = the effective row came from the global default (no tenant override)
}

// GetEffectiveProvider returns the tenant's effective provider (own row, else global), redacted.
func (r *Repository) GetEffectiveProvider(ctx context.Context, tenantID uuid.UUID) (ProviderView, bool, error) {
	row, _, err := r.ProviderConfig(ctx, tenantID)
	if err != nil {
		return ProviderView{}, false, err
	}
	if !row.HasRow {
		return ProviderView{}, false, nil
	}
	return ProviderView{Kind: row.Kind, BaseURL: row.BaseURL, Model: row.Model, HasKey: row.APIKeyRef != "", Global: row.IsGlobal}, true, nil
}

// GetGlobalProvider reads the global (tenant_id NULL) default row, redacted. Platform-admin, system context.
func (r *Repository) GetGlobalProvider(ctx context.Context) (ProviderView, bool, error) {
	var v ProviderView
	found := false
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var baseURL, apiKeyRef *string
		var kind, model string
		e := tx.QueryRow(ctx, `SELECT provider_kind, base_url, model, api_key_ref FROM ai_provider WHERE tenant_id IS NULL`).
			Scan(&kind, &baseURL, &model, &apiKeyRef)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		v = ProviderView{Kind: ProviderKind(kind), Model: model, HasKey: apiKeyRef != nil, Global: true}
		if baseURL != nil {
			v.BaseURL = *baseURL
		}
		return nil
	})
	return v, found, err
}

// ListAllowedEndpoints returns the platform trust list.
func (r *Repository) ListAllowedEndpoints(ctx context.Context) ([]AllowedEndpoint, error) {
	var out []AllowedEndpoint
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id, scheme, host, port, note FROM ai_provider_allowed_endpoint ORDER BY host, port`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a AllowedEndpoint
			if e := rows.Scan(&a.ID, &a.Scheme, &a.Host, &a.Port, &a.Note); e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// AddAllowedEndpoint inserts a trust-list entry (idempotent on scheme+host+port).
func (r *Repository) AddAllowedEndpoint(ctx context.Context, scheme, host string, port int, note string) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO ai_provider_allowed_endpoint (scheme, host, port, note) VALUES ($1,$2,$3,$4)
			ON CONFLICT (scheme, host, port) DO UPDATE SET note = EXCLUDED.note`, scheme, host, port, note)
		return e
	})
}

// DeleteAllowedEndpoint removes a trust-list entry by id.
func (r *Repository) DeleteAllowedEndpoint(ctx context.Context, id uuid.UUID) error {
	return r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM ai_provider_allowed_endpoint WHERE id=$1`, id)
		return e
	})
}

// GetTenantPolicy returns a tenant's allowed_kinds (default all if unset).
func (r *Repository) GetTenantPolicy(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	_, allowed, err := r.ProviderConfig(ctx, tenantID)
	return allowed, err
}

// SetTenantPolicy upserts a tenant's allowed_kinds. Platform-admin sets it (WithTenant(target) satisfies the RLS
// check); a tenant can never widen it because the tenant provider endpoint validates kind∈allowed, not this table.
func (r *Repository) SetTenantPolicy(ctx context.Context, tenantID uuid.UUID, kinds []string) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO tenant_ai_policy (tenant_id, allowed_kinds, updated_at) VALUES ($1,$2,now())
			ON CONFLICT (tenant_id) DO UPDATE SET allowed_kinds = EXCLUDED.allowed_kinds, updated_at = now()`, tenantID, kinds)
		return e
	})
}
