package incident

import (
	"context"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository persists incidents and timeline entries (tenant-scoped).
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// CreateTx inserts an incident within an existing transaction.
func (r *Repository) CreateTx(ctx context.Context, tx pgx.Tx, i *Incident) error {
	return tx.QueryRow(ctx,
		`INSERT INTO incidents (id, tenant_id, title, severity, category, stage, owner_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
		i.ID, i.TenantID, i.Title, i.Severity, i.Category, i.Stage, i.OwnerID,
	).Scan(&i.CreatedAt)
}

// AddTimelineTx inserts a timeline entry within an existing transaction.
func (r *Repository) AddTimelineTx(ctx context.Context, tx pgx.Tx, e *TimelineEntry) error {
	return tx.QueryRow(ctx,
		`INSERT INTO incident_timeline (id, incident_id, author, kind, note)
		 VALUES ($1,$2,$3,$4,$5) RETURNING at`,
		e.ID, e.IncidentID, e.Author, e.Kind, e.Note,
	).Scan(&e.At)
}

// List returns incidents for a tenant.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Incident, error) {
	var out []Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at
			   FROM incidents ORDER BY created_at DESC LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i Incident
			if err := rows.Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category,
				&i.Stage, &i.OwnerID, &i.CreatedAt, &i.ClosedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one incident.
func (r *Repository) Get(ctx context.Context, tenantID, id uuid.UUID) (*Incident, error) {
	var i Incident
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, title, severity, category, stage, owner_id, created_at, closed_at
			   FROM incidents WHERE id=$1`, id,
		).Scan(&i.ID, &i.TenantID, &i.Title, &i.Severity, &i.Category, &i.Stage, &i.OwnerID, &i.CreatedAt, &i.ClosedAt)
	})
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ListTimeline returns an incident's timeline.
func (r *Repository) ListTimeline(ctx context.Context, tenantID, id uuid.UUID) ([]TimelineEntry, error) {
	var out []TimelineEntry
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, incident_id, at, author, kind, note FROM incident_timeline
			  WHERE incident_id=$1 ORDER BY at ASC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e TimelineEntry
			if err := rows.Scan(&e.ID, &e.IncidentID, &e.At, &e.Author, &e.Kind, &e.Note); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// AddNote appends a note to an incident's timeline.
func (r *Repository) AddNote(ctx context.Context, tenantID uuid.UUID, e *TimelineEntry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return r.AddTimelineTx(ctx, tx, e)
	})
}

// Close marks an incident closed and records a timeline entry.
func (r *Repository) Close(ctx context.Context, tenantID, id uuid.UUID, e *TimelineEntry) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE incidents SET stage='closed', closed_at=now() WHERE id=$1 AND stage <> 'closed'`, id)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return r.AddTimelineTx(ctx, tx, e)
	})
}

// CreateFromAlertTx runs the promote-to-incident write atomically: create the
// incident, mark the alert promoted, and seed the timeline. The caller supplies
// a promote callback so the alert repo stays the owner of its own table.
func (r *Repository) CreateFromAlertTx(ctx context.Context, tenantID uuid.UUID, i *Incident, seed *TimelineEntry, promote func(ctx context.Context, tx pgx.Tx, incidentID uuid.UUID) error) error {
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := r.CreateTx(ctx, tx, i); err != nil {
			return err
		}
		if err := promote(ctx, tx, i.ID); err != nil {
			return err
		}
		seed.IncidentID = i.ID
		return r.AddTimelineTx(ctx, tx, seed)
	})
}
