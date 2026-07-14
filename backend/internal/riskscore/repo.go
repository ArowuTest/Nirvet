package riskscore

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ArowuTest/nirvet/internal/platform/audit"
	"github.com/ArowuTest/nirvet/internal/platform/auth"
	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Store resolves and persists the per-tenant risk_score_config. A tenant with no row inherits DefaultConfig
// (which mirrors the migration's seeded column defaults) — fail-safe, never a zero/empty config.
type Store struct{ db *database.DB }

// NewStore builds the config store.
func NewStore(db *database.DB) *Store { return &Store{db: db} }

// Resolve returns the tenant's effective config: its row decoded onto DefaultConfig, or DefaultConfig if no row.
func (s *Store) Resolve(ctx context.Context, tenantID uuid.UUID) (Config, error) {
	cfg := DefaultConfig()
	var (
		ew, cw, ow float64
		bands, mdl []byte
	)
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT exposure_weight, compliance_weight, operational_weight, bands, model_params
			   FROM risk_score_config WHERE tenant_id=$1`, tenantID).
			Scan(&ew, &cw, &ow, &bands, &mdl)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cfg, nil // no row → seeded default
		}
		return cfg, err
	}
	cfg.ExposureWeight, cfg.ComplianceWeight, cfg.OperationalWeight = ew, cw, ow
	if len(bands) > 0 {
		_ = json.Unmarshal(bands, &cfg.Bands)
	}
	if len(mdl) > 0 {
		_ = json.Unmarshal(mdl, &cfg.Model)
	}
	return cfg, nil
}

// Set validates and upserts the tenant's config (append-only audited). A tenant_id-scoped upsert under RLS.
func (s *Store) Set(ctx context.Context, p auth.Principal, tenantID uuid.UUID, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	bands, _ := json.Marshal(cfg.Bands)
	mdl, _ := json.Marshal(cfg.Model)
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO risk_score_config
			   (tenant_id, exposure_weight, compliance_weight, operational_weight, bands, model_params, updated_by, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,now())
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   exposure_weight=$2, compliance_weight=$3, operational_weight=$4,
			   bands=$5, model_params=$6, updated_by=$7, updated_at=now()`,
			tenantID, cfg.ExposureWeight, cfg.ComplianceWeight, cfg.OperationalWeight, bands, mdl, p.UserID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Entry{
			ActorID: p.UserID, ActorEmail: p.Email, Action: "riskscore.config_set",
			Target: "tenant:" + tenantID.String(),
		})
	})
}
