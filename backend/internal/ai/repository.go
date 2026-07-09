package ai

// §6.12 #117 A-3 — config reads for the provider resolver. All reads run in the tenant's RLS context: ai_provider
// is visible as own-or-global (tenant row wins), tenant_ai_policy as own, ai_provider_allowed_endpoint is
// platform-global (no RLS, GRANT SELECT). Writes (config surface) land in A-4.

import (
	"context"
	"errors"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository reads the AI provider configuration.
type Repository struct{ db *database.DB }

// NewRepository builds the config reader.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// providerRow is the resolved ai_provider record (tenant override or global default).
type providerRow struct {
	Kind      ProviderKind
	BaseURL   string // "" when NULL (non-openai kinds)
	Model     string
	APIKeyRef string // "" when NULL (keyless local model, or anthropic-from-config default)
	HasRow    bool
}

// allKinds is the default policy when a tenant has no tenant_ai_policy row: every kind permitted.
var allKinds = []string{string(KindAnthropic), string(KindOpenAICompatible), string(KindDisabled)}

// ProviderConfig loads, in one tenant-scoped tx, the effective provider row (tenant wins over global) and the
// tenant's allowed_kinds (default = all). A missing provider row → HasRow=false (resolver fails closed to disabled).
func (r *Repository) ProviderConfig(ctx context.Context, tenantID uuid.UUID) (providerRow, []string, error) {
	var row providerRow
	allowed := append([]string(nil), allKinds...)
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Tenant row wins over the global (NULL) row: NULLS LAST puts the tenant's own row first.
		var baseURL, apiKeyRef *string
		var kind, model string
		qerr := tx.QueryRow(ctx, `
			SELECT provider_kind, base_url, model, api_key_ref
			  FROM ai_provider
			 WHERE tenant_id = app_current_tenant() OR tenant_id IS NULL
			 ORDER BY tenant_id NULLS LAST
			 LIMIT 1`).Scan(&kind, &baseURL, &model, &apiKeyRef)
		switch {
		case errors.Is(qerr, pgx.ErrNoRows):
			// leave HasRow=false
		case qerr != nil:
			return qerr
		default:
			row.HasRow = true
			row.Kind = ProviderKind(kind)
			row.Model = model
			if baseURL != nil {
				row.BaseURL = *baseURL
			}
			if apiKeyRef != nil {
				row.APIKeyRef = *apiKeyRef
			}
		}
		// tenant_ai_policy (own row). Absent → default all kinds.
		var kinds []string
		perr := tx.QueryRow(ctx, `SELECT allowed_kinds FROM tenant_ai_policy WHERE tenant_id = app_current_tenant()`).Scan(&kinds)
		switch {
		case errors.Is(perr, pgx.ErrNoRows):
			// keep default allKinds
		case perr != nil:
			return perr
		default:
			if len(kinds) > 0 {
				allowed = kinds
			}
		}
		return nil
	})
	if err != nil {
		return providerRow{}, nil, err
	}
	return row, allowed, nil
}

// IsAllowedEndpoint reports whether (scheme, host, port) is on the platform-admin trust list. port 0 = default port.
// This is the data-egress / residency boundary (§1903): the only hosts a tenant's data may be sent to.
func (r *Repository) IsAllowedEndpoint(ctx context.Context, tenantID uuid.UUID, scheme, host string, port int) (bool, error) {
	var ok bool
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM ai_provider_allowed_endpoint
				 WHERE scheme = $1 AND host = $2 AND port = $3
			)`, scheme, host, port).Scan(&ok)
	})
	return ok, err
}
