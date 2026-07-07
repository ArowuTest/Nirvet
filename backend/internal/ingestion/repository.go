package ingestion

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/jackc/pgx/v5"
)

// Repository persists raw events (tenant-scoped, evidence record).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// StoreRaw inserts an immutable raw event, idempotent on (tenant, dedupe_key).
// Returns true if the row was newly inserted (false = duplicate re-ingest).
func (r *Repository) StoreRaw(ctx context.Context, e *RawEvent) (bool, error) {
	inserted := false
	err := r.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`INSERT INTO raw_events (id, tenant_id, source, dedupe_key, checksum, blob_uri, payload)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
			e.ID, e.TenantID, e.Source, e.DedupeKey, e.Checksum, e.BlobURI, e.Payload,
		)
		if err != nil {
			return err
		}
		inserted = ct.RowsAffected() > 0
		return nil
	})
	return inserted, err
}
