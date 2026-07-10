package investigation

// §6.9 #124 I-1/I-2 — the DB layer. The hunt query runs under WithTenant so RLS FORCE is the backstop even if the
// compiled predicate were wrong (defense in depth); the read-path audit is a tenant-scoped append-only insert.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Repository reads events and writes the investigation read-audit.
type Repository struct{ db *database.DB }

// NewRepository builds the repository.
func NewRepository(db *database.DB) *Repository { return &Repository{db: db} }

// eventProjection is the SAFE column subset returned by a hunt query (no raw data / raw_pointer).
const eventProjection = `id, observed_at, collected_at, source, class_name, activity_name, severity, confidence, actor_ref, target_ref, action, outcome, mitre, vendor, product`

// RunHunt executes a compiled query against `events` under the tenant's RLS context and returns the projected rows.
// The SQL text is a fixed SELECT + the compiled WHERE (registry columns + $N placeholders only) + a bound LIMIT.
func (r *Repository) RunHunt(ctx context.Context, tenantID uuid.UUID, c compiled, limit int) ([]EventRow, error) {
	args := append(append([]any{}, c.args...), limit)
	sql := `SELECT ` + eventProjection + ` FROM events WHERE ` + c.where +
		` ORDER BY observed_at DESC LIMIT $` + fmt.Sprint(len(args))
	var out []EventRow
	err := r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e EventRow
			if err := rows.Scan(&e.ID, &e.EventTime, &e.IngestTime, &e.Source, &e.Class, &e.Activity,
				&e.Severity, &e.Confidence, &e.ActorRef, &e.TargetRef, &e.Action, &e.Outcome,
				&e.MITRE, &e.Vendor, &e.Product); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// LoadLimits reads the seeded global cost ceiling (no-hardcoding). On ANY error it returns the code default so a
// missing/broken config row can never REMOVE the ceiling (fail-safe toward the bound, not toward unbounded).
func (r *Repository) LoadLimits(ctx context.Context) Limits {
	var mp, days, dl, ml int
	err := r.db.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT max_predicates, max_time_span_days, default_limit, max_limit FROM investigation_limits WHERE scope='global'`).
			Scan(&mp, &days, &dl, &ml)
	})
	if err != nil || mp <= 0 || days <= 0 || dl <= 0 || ml <= 0 {
		return DefaultLimits()
	}
	return Limits{MaxPredicates: mp, MaxTimeSpan: time.Duration(days) * 24 * time.Hour, DefaultLimit: dl, MaxLimit: ml}
}

// WriteQueryAudit records one read-path audit row (INV-007): who ran what query and how many rows it returned. Append-
// only + tenant-scoped. One row per execution.
func (r *Repository) WriteQueryAudit(ctx context.Context, tenantID, actorID uuid.UUID, kind string, query any, rowCount int) error {
	qj, err := json.Marshal(query)
	if err != nil {
		qj = []byte("{}")
	}
	return r.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO investigation_query_audit (tenant_id, actor_id, kind, query, row_count) VALUES ($1,$2,$3,$4,$5)`,
			tenantID, actorID, kind, qj, rowCount)
		return e
	})
}
