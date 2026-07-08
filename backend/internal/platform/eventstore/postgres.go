package eventstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PostgresStore is the MVP EventStore backend (ADR-0002). Events live in a
// tenant-partitioned table; every access is tenant-scoped via the DB helper so
// RLS applies. Swap this for a ClickHouse implementation at V1.
type PostgresStore struct {
	db *database.DB
}

// NewPostgres builds a Postgres-backed event store.
func NewPostgres(db *database.DB) *PostgresStore { return &PostgresStore{db: db} }

// Append inserts events idempotently (ON CONFLICT (tenant_id, dedupe_key) DO
// NOTHING) and returns the count newly inserted.
func (s *PostgresStore) Append(ctx context.Context, tenantID uuid.UUID, events []NormalizedEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	inserted := 0
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		for _, e := range events {
			data, err := json.Marshal(e.Data)
			if err != nil {
				data = []byte("{}")
			}
			id := e.ID
			if id == uuid.Nil {
				id = uuid.New()
			}
			if e.CollectedAt.IsZero() {
				e.CollectedAt = time.Now()
			}
			if e.SchemaVersion == "" {
				e.SchemaVersion = CanonicalSchemaVersion
			}
			ct, err := tx.Exec(ctx,
				`INSERT INTO events
				  (id, schema_version, dedupe_key, source, connector_id, collected_at, observed_at,
				   class_name, activity_name, severity, confidence,
				   actor_ref, target_ref, action, outcome, raw_pointer, checksum, data)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
				 ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
				id, e.SchemaVersion, e.DedupeKey, e.Source, e.ConnectorID, e.CollectedAt, e.ObservedAt,
				e.ClassName, e.ActivityName, e.Severity, e.Confidence,
				e.ActorRef, e.TargetRef, e.Action, e.Outcome, e.RawPointer, e.Checksum, data,
			)
			if err != nil {
				return fmt.Errorf("eventstore: append: %w", err)
			}
			inserted += int(ct.RowsAffected())
		}
		return nil
	})
	return inserted, err
}

// Query returns matching events for the tenant, newest first.
func (s *PostgresStore) Query(ctx context.Context, tenantID uuid.UUID, q Query) ([]NormalizedEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	var out []NormalizedEvent
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, schema_version, dedupe_key, source, connector_id, collected_at, observed_at,
			        class_name, activity_name, severity, confidence,
			        actor_ref, target_ref, action, outcome, raw_pointer, checksum, data
			   FROM events
			  WHERE ($1::timestamptz IS NULL OR observed_at >= $1)
			    AND ($2::timestamptz IS NULL OR observed_at <= $2)
			    AND ($3 = '' OR severity = $3)
			    AND ($4 = '' OR class_name ILIKE '%'||$4||'%' OR action ILIKE '%'||$4||'%'
			                 OR actor_ref ILIKE '%'||$4||'%' OR target_ref ILIKE '%'||$4||'%')
			  ORDER BY observed_at DESC
			  LIMIT $5`,
			nullableTime(q.From), nullableTime(q.To), q.Severity, q.Search, q.Limit,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e NormalizedEvent
			var data []byte
			if err := rows.Scan(&e.ID, &e.TenantID, &e.SchemaVersion, &e.DedupeKey, &e.Source, &e.ConnectorID,
				&e.CollectedAt, &e.ObservedAt, &e.ClassName, &e.ActivityName, &e.Severity,
				&e.Confidence, &e.ActorRef, &e.TargetRef, &e.Action, &e.Outcome,
				&e.RawPointer, &e.Checksum, &data); err != nil {
				return err
			}
			_ = json.Unmarshal(data, &e.Data)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// CountSince counts a tenant's events observed at or after `since` (tenant-scoped
// via RLS).
func (s *PostgresStore) CountSince(ctx context.Context, tenantID uuid.UUID, since time.Time) (int, error) {
	var n int
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE observed_at >= $1`, since).Scan(&n)
	})
	return n, err
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
