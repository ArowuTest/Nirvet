package ingestion

import (
	"context"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
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

// MarkEnqueued records that a raw event's normalize job has been enqueued
// (durability marker, migration 0018). Best-effort: if this write is lost, the
// reconciler re-enqueues the job, which is idempotent downstream.
func (r *Repository) MarkEnqueued(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE raw_events SET enqueued_at=now() WHERE id=$1`, id)
		return err
	})
}

// UnenqueuedRaw is a raw event whose normalize job was never enqueued.
type UnenqueuedRaw struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	DedupeKey string
	Checksum  string
	BlobURI   string
}

// FindUnenqueued returns raw events still awaiting their normalize job and older than
// olderThan. It runs at the system level (spans tenants) through the SECURITY DEFINER
// ingest_unenqueued_raw function, because raw_events has RLS FORCEd and the reconciler
// has no single tenant context.
func (r *Repository) FindUnenqueued(ctx context.Context, olderThan time.Time, limit int) ([]UnenqueuedRaw, error) {
	var out []UnenqueuedRaw
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, dedupe_key, checksum, blob_uri
			   FROM ingest_unenqueued_raw($1, $2)`, olderThan, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u UnenqueuedRaw
			if err := rows.Scan(&u.ID, &u.TenantID, &u.DedupeKey, &u.Checksum, &u.BlobURI); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}
